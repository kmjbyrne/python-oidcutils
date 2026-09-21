# oidcutils

A Python SDK that wraps [Authlib](https://authlib.org/) and
[joserfc](https://jose.authlib.org/) to handle OAuth2/OIDC token validation, and
builds a `Principal` identity model from JWT claims. Optional
[FastAPI](https://fastapi.tiangolo.com/) integration exposes `current_user` and
`require_permission` as dependency functions, so service teams add auth to
routes without touching JWTs directly.

It also does the other half, for services that have to obtain a token rather
than just check one. `OIDCClient` sends a browser to the identity server,
exchanges the code it comes back with, and refreshes the token set before it
expires.

An API serving machine callers never needs that, anything with a sign-in button
does.

Start at [browser login](#browser-login) if that is you.

## Install

Not on PyPI at the moment. Install directly from GitHub:

```bash
uv add git+https://github.com/kmjbyrne/python-oidcutils.git
```

For FastAPI support:

```bash
uv add "oidcutils[fastapi] @ git+https://github.com/kmjbyrne/python-oidcutils.git"
```

Pin to a version tag:

```bash
uv add git+https://github.com/kmjbyrne/python-oidcutils.git@v0.0.3-beta
```

## How Validation Works

Token validation uses OIDC discovery to find the JWKS endpoint, fetches the
signing keys, and caches them. When the SDK encounters an unknown key ID, it
refreshes the JWKS automatically to handle key rotation.

RBAC adds no extra verification. Roles and permissions live inside the JWT
claims. After the single token validation, the SDK checks the `Principal` fields
in memory.

## Checking A Token

`TokenValidator` is the whole of it. Give it an issuer and an audience, hand it
a token, and get a `Principal` back.

```python
from oidcutils import TokenValidator, Principal

validator = TokenValidator(
    issuer="https://id.example.com",
    audience="my-api",
)

principal: Principal = await validator.validate_token(token)
principal.subject  # "user-123"
principal.has_role("admin")
principal.has_permission("orders.write")
```

## Browser Login

Signing somebody in is three calls on `OIDCClient`, and since it imports no
framework this is the same however you happen to serve HTTP:

```python
from oidcutils import OIDCClient

client = OIDCClient(
    issuer="https://id.example.com",
    client_id="my-app",
    client_secret="secret",
    redirect_uri="https://my-app.example.com/auth/callback",
)

# On your /login route: send the browser to `url` and keep `state`.
url, state = await client.authorization_url()

# On your /callback route, with the code the identity server sent back.
token_set = await client.exchange_code(code)

# Later, when the access token nears expiry. See Token Refresh below.
token_set = await client.refresh(token_set.refresh_token)
```

`redirect_uri` has to match what the identity server has registered for this
client, exactly. Most providers compare it as a string, so a trailing slash or a
different host is a refused login rather than a warning. It names a route on
your service: deriving it from the issuer sends the browser back to the identity
server, which has no callback to answer with.

There is bookkeeping around those calls that somebody has to own: the pending
states between the redirect and the callback, the token set stored against a
session id, and the cookie that names it. If you are on FastAPI,
`create_auth_router` does all of that for you.

## Token Refresh

`TokenManager` sits over a `TokenStore` and refreshes when the access token is
near expiry, so callers ask for a token and get a valid one.

`create_auth_router` builds one for you. Construct it directly when you are
holding tokens obtained some other way, or when you need a store that outlives
the process.

```python
from oidcutils import OIDCClient, TokenManager

client = OIDCClient(
    issuer="https://id.example.com",
    client_id="my-app",
    client_secret="secret",
    redirect_uri="https://my-app.example.com/auth/callback",
)

manager = TokenManager(client)

# `code` is the query parameter the identity server sends to redirect_uri.
# create_auth_router does this exchange itself; do it by hand only when you
# are not using that router.
token_set = await client.exchange_code(code)
await manager.store_token(session_id, token_set)

# On subsequent requests, get a valid access token (auto-refreshes)
access_token = await manager.get_access_token(session_id)
```

Implement the `TokenStore` protocol to plug in your own storage backend (Redis,
database, encrypted cookies).

`get_access_token` does not single-flight the refresh. Several requests that
notice expiry together each send the refresh token, and a provider that rotates
on every use may read the second as reuse and revoke the family. Wrap it in your
own lock where that matters.

## Using It With FastAPI

`oidcutils.contrib.fastapi` covers both halves. Checking tokens first, since
that is what most services want.

Put a `FastAPIAuth` on `app.state` and the dependency functions find it:

```python
from fastapi import Depends, FastAPI
from oidcutils.contrib.fastapi import FastAPIAuth, current_user, require_permission
from oidcutils import Principal

app = FastAPI()
app.state.auth = FastAPIAuth(
    issuer="https://id.example.com",
    audience="my-api",
)


@app.get("/orders")
async def list_orders(user: Principal = Depends(current_user)):
    return {"user": user.subject}


@app.post("/orders")
async def create_order(
    user: Principal = Depends(require_permission("orders.write")),
):
    return {"created_by": user.subject}
```

There are two other wiring patterns, dependency overrides and router factories,
in [docs/guide/fastapi-integration.md](docs/guide/fastapi-integration.md).

### Signing Somebody In

`create_auth_router` takes the client from [browser login](#browser-login) and
gives you the flow as two routes, holding the pending states and the session
store itself. The browser only ever sees a redirect and a cookie, never client
credentials or tokens.

```python
from fastapi import FastAPI
from oidcutils import OIDCClient
from oidcutils.contrib.fastapi import FastAPIAuth, create_auth_router

app = FastAPI()

client = OIDCClient(
    issuer="https://id.example.com",
    client_id="my-app",
    client_secret="secret",
    redirect_uri="https://my-app.example.com/auth/callback",
)

# /login sends the browser to the identity server.
# /callback exchanges the code and sets an httpOnly session cookie.
app.include_router(create_auth_router(client), prefix="/auth")

# The resource half, for the API routes the signed-in browser then calls.
app.state.auth = FastAPIAuth(issuer="https://id.example.com", audience="my-api")
```

That leaves the cookie the callback set and routes that read a bearer token, so
bind `session_principal` to join them. See
[Connecting An IdP](docs/guide/connecting-an-idp.md) for the whole wiring.

The default `TokenStore` is in memory, which means a restart signs everybody out
and two workers do not share sessions. Pass a `TokenManager` backed by your own
store for anything beyond a single process.

## Local Development

Run a development identity provider with no external provider and nothing to
configure:

```bash
uv run python -m oidcutils.idp --port 9000 --audience my-api
```

It serves discovery, JWKS and `POST /dev/token`, signing with an ES256 key
generated in memory. Point your app at it:

```bash
OIDC_ISSUER=http://127.0.0.1:9000
OIDC_AUDIENCE=my-api
```

Mint a token with whatever claims a test needs:

```bash
curl -s -XPOST http://127.0.0.1:9000/dev/token \
  -H 'Content-Type: application/json' \
  -d '{"subject": "user-1", "roles": ["admin"]}'
```

Built on `http.server`, so it needs nothing beyond this package. Supply
`--signing-key` or `OIDC_DEV_SIGNING_KEY` where tokens have to survive a
restart. For a single-process loop, `create_dev_idp` returns the same provider
as a mountable app.

### Signing In Locally

`FastAPIAuth.mount_dev` gives an app a working browser login with nothing
external running: the provider, an authorization page listing who to be, and the
`/login` and `/callback` routes that drive the flow.

```python
from oidcutils.contrib.fastapi import FastAPIAuth, current_user
from oidcutils.dev import DevPersona

PERSONAS = [
    DevPersona(key="alice", subject="u-alice", name="Alice Admin",
               email="alice@acme.example", purpose="Owns Acme", roles=("admin",)),
    DevPersona(key="bob", subject="u-bob", name="Bob Editor",
               purpose="Member of Acme"),
]

auth = FastAPIAuth.mount_dev(app, issuer, audience, PERSONAS)
app.dependency_overrides[current_user] = auth.get_principal
```

`/auth/login` redirects to a page listing them, picking one redirects back with
a code, and the browser leaves holding a session cookie. The same routes work
unchanged against a real provider: only the issuer differs.

A persona carries what an identity server knows, which is identity and the roles
it issues. Not memberships: those are your application's concept, read per
request from rows it owns. The subject is the join between the two, so the
personas and your own fixtures have to name the same ids. See
[docs/examples/local-dev.md](docs/examples/local-dev.md).

Without `personas` the provider mints tokens and serves no authorization page,
which is enough for exercising the resource half by hand: mint a token, send it
as a bearer header, and call the routes behind `current_user`.

It issues a signed token to anyone who asks, so it belongs on a developer's
machine and nowhere else. See [Local Development](docs/examples/local-dev.md).

## Custom Claim Mapping

If your IdP uses non-standard claim names, configure the mapper:

```python
from oidcutils.claims import DefaultClaimMapper

mapper = DefaultClaimMapper(
    roles_claim="realm_roles",
    permissions_claim="scope_perms",
    tenant_claim="org_id",
)
```

Or implement the `ClaimMapper` protocol for full control over how JWT claims
become a `Principal`.

## The Principal Model

| Field         | Type               | Source claim |
| ------------- | ------------------ | ------------ |
| `subject`     | `str`              | `sub`        |
| `issuer`      | `str`              | `iss`        |
| `audience`    | `str \| list[str]` | `aud`        |
| `email`       | `str \| None`      | `email`      |
| `name`        | `str \| None`      | `name`       |
| `tenant_id`   | `str \| None`      | configurable |
| `roles`       | `frozenset[str]`   | configurable |
| `permissions` | `frozenset[str]`   | configurable |
| `raw_claims`  | `dict`             | full JWT     |

Helper methods: `has_role()`, `has_permission()`, `has_any_role()`,
`has_all_permissions()`.

## Architecture

```text
oidcutils/
├── principal.py          # Identity model
├── claims.py             # Claim-to-Principal mapping
├── resource.py           # Token validation (joserfc)
├── client.py             # OIDC client (Authlib)
├── tokens.py             # Token storage and auto-refresh
├── dev.py                # Dev signing key, minting, JWKS, discovery
├── idp.py                # Standalone dev provider (http.server)
├── mint.py               # Mint a dev token from the command line
├── testing.py            # Test helpers for apps using the SDK
└── contrib/
    └── fastapi.py        # FastAPI dependency functions
```

The core package depends on [Authlib](https://authlib.org/) (OAuth2 client),
[joserfc](https://jose.authlib.org/) (JWT/JWKS validation), and
[httpx](https://www.python-httpx.org/) (async HTTP). The FastAPI adapter is an
optional extra. Swapping out the JWT library later changes `resource.py` only;
the `Principal` model and contrib layer stay stable.

## Development

```bash
uv sync --dev
uv run pytest tests/ -v
bin/lint
```
