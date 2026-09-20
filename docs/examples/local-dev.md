# Local Development

A self-contained setup for testing the SDK without a real identity provider. See
`examples/combined.py`.

## What's Included

Two FastAPI applications behind subdomain routing on a single port:

- **`auth.127.0.0.1.nip.io:8000`** -- a fake OIDC provider that mints JWT access
  tokens and serves discovery/JWKS
- **`api.127.0.0.1.nip.io:8000`** -- an example resource server that validates
  tokens using the SDK

Both names resolve to `127.0.0.1` through [nip.io](https://nip.io), so no hosts
file is needed. Browsers treat them as separate origins, which is what makes
`SameSite=Strict` cookies behave as they would in production.

## Running It

```bash
uv run uvicorn examples.combined:app --port 8000
```

!!! warning "Use port 8000" The issuer URL is built from a `PORT` constant in
the example, and the token `iss` claim and discovery document are pinned to it.
Serving on another port makes the API validate tokens against an issuer that is
not listening, and every authenticated request fails with a connection error.

## Test the Flow

Mint a token:

```bash
TOKEN=$(curl -s http://auth.127.0.0.1.nip.io:8000/token \
  -H 'Content-Type: application/json' \
  -d '{"subject": "user-1", "roles": ["admin"], "permissions": ["orders.read", "orders.write"]}' \
  | python -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
```

Use it:

```bash
curl -s http://api.127.0.0.1.nip.io:8000/me -H "Authorization: Bearer $TOKEN" | python -m json.tool
curl -s http://api.127.0.0.1.nip.io:8000/orders -H "Authorization: Bearer $TOKEN" | python -m json.tool
```

Test denied access:

```bash
TOKEN_VIEWER=$(curl -s http://auth.127.0.0.1.nip.io:8000/token \
  -H 'Content-Type: application/json' \
  -d '{"subject": "user-2", "roles": ["viewer"]}' \
  | python -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# 403 -- no orders.write permission
curl -s http://api.127.0.0.1.nip.io:8000/orders -X POST -H "Authorization: Bearer $TOKEN_VIEWER"

# 403 -- no admin role
curl -s http://api.127.0.0.1.nip.io:8000/admin -H "Authorization: Bearer $TOKEN_VIEWER"
```

Missing and malformed tokens are rejected before any role check:

```bash
# 401 -- no credentials
curl -s -o /dev/null -w '%{http_code}\n' http://api.127.0.0.1.nip.io:8000/me

# 401 -- not a valid token
curl -s -o /dev/null -w '%{http_code}\n' http://api.127.0.0.1.nip.io:8000/me \
  -H 'Authorization: Bearer garbage'
```

## Browser Flow

Open <http://api.127.0.0.1.nip.io:8000/auth/login> to exercise the authorization
code flow. It redirects through the IdP, exchanges the code, and sets an
httponly `session_id` cookie.

Form parsing at the token endpoint needs `python-multipart`, which the browser
flow uses and the curl flow above does not:

```bash
uv add --dev python-multipart
```

!!! note "The landing page returns 401" `post_login_redirect` sends the browser
to `/me`, which depends on `current_user` and therefore reads a bearer header,
not the session cookie. The cookie is set correctly; nothing in the example
exchanges it for a principal. Resolving the session into an access token is the
application's job -- see [Token Refresh](../guide/token-refresh.md) for
`TokenManager`, which is what `create_auth_router` stores the token set in.

## Without The Example App

`examples/combined.py` is a full IdP: an authorization endpoint, a code flow,
subdomain routing. When all you need is tokens with particular roles, the SDK
can mount a minimal dev provider into your own app instead.

Set `OIDC_BYPASS` and call `configure`:

```python
from oidcutils.contrib.fastapi import OIDCSettings, configure


class Settings(OIDCSettings, BaseSettings):
    OIDC_ISSUER: str = "http://localhost:8000"
    OIDC_AUDIENCE: str = "dev"
    OIDC_BYPASS: bool = False


configure(app, settings)
```

With `OIDC_BYPASS` true, `configure` mounts discovery, JWKS and a
`POST /dev/token` endpoint on the app, then points the validator at them. It
sets `app.state.auth` either way, so routes and guards are unchanged. With it
false you get the ordinary `FastAPIAuth` against your real provider.

Mint a token with whatever claims the test needs:

```bash
curl -s -X POST http://localhost:8000/dev/token \
  -H 'Content-Type: application/json' \
  -d '{"subject": "user-1", "roles": ["admin"], "permissions": ["orders.write"]}'
```

The endpoint fills in the issuer and audience from settings. Passing either in
the body raises a `TypeError`, because they are already bound.

!!! danger "Development only" The dev provider issues a signed token to any
unauthenticated caller, with any roles they ask for. Guard `OIDC_BYPASS` so it
can never be true outside development, for example by rejecting it in a settings
validator.

## A Standalone Provider

The options above mount the provider into the application validating against it,
which means the app fetches its signing key from itself. That works, but it is
one more thing behaving differently from production.

`python -m oidcutils.idp` runs the provider as its own process instead:

```bash
uv run python -m oidcutils.idp --port 9000 --audience my-api
```

It prints the issuer to set, and the app then points at it like any other
provider:

```bash
OIDC_ISSUER=http://127.0.0.1:9000
OIDC_AUDIENCE=my-api
```

Nothing is mounted and no transport is injected. The app fetches discovery and
JWKS over a socket, which is the path it will take against a real issuer.

It is built on `http.server`, so it runs with no extra dependencies: the
`fastapi` extra is not needed.

Mint a token the same way:

```bash
curl -s -XPOST http://127.0.0.1:9000/dev/token \
  -H 'Content-Type: application/json' \
  -d '{"subject": "user-1", "roles": ["admin"]}'
```

`serve()` returns the server without starting it, so a test can bind port 0 and
read back the port it was given:

```python
import threading

from oidcutils.idp import serve

server = serve(port=0, audience="my-api")
threading.Thread(target=server.serve_forever, daemon=True).start()
issuer = f"http://127.0.0.1:{server.server_address[1]}"
```

## Mounting It In One Process

Where a second process is unwelcome, `create_dev_idp` returns the provider as an
app to mount:

```python
from oidcutils.contrib.fastapi import create_dev_idp, dev_auth

idp = create_dev_idp(issuer="http://localhost:8000/idp", audience="my-api")
app.mount("/idp", idp)

auth = dev_auth(app, issuer="http://localhost:8000/idp", audience="my-api")
```

The issuer must include the mount path, since the discovery document it
publishes has to name endpoints a client can reach.

A mounted app is not listening on a port, and a test has no server at all, so
the validator cannot fetch keys over the network. `dev_auth` builds auth whose
HTTP client hands requests straight to the app through `httpx.ASGITransport`.
Pass the parent app, since that is what the mount is reachable through.

`FastAPIAuth` takes `http_client` directly if you would rather assemble it
yourself.

## Signing In With A Persona

Everything above hands out tokens on request, which tests a resource server but
not a sign-in. `FastAPIAuth.mount_dev` adds the missing half: an authorization
page listing people to be, wired to the `/login` and `/callback` routes a real
provider would drive.

```python
from fastapi import FastAPI
from oidcutils.contrib.fastapi import FastAPIAuth, current_user
from oidcutils.dev import DevPersona

PERSONAS = [
    DevPersona(
        key="alice",
        subject="019b76da-b3b8-741c-ada2-4c1da1ed4927",
        name="Alice Admin",
        email="alice@acme.example",
        purpose="Owns Acme. Has a personal space too.",
        roles=("admin",),
    ),
    DevPersona(
        key="nomad",
        subject="019b76da-c358-7972-b57c-06ae0972b8e2",
        name="Noa Nomad",
        purpose="No space and no organization: every resource refuses.",
    ),
]

app = FastAPI()
auth = FastAPIAuth.mount_dev(app, "http://localhost:8000", "my-api", PERSONAS)
app.dependency_overrides[current_user] = auth.get_principal
```

`/auth/login` then redirects to a page listing Alice and Noa. Picking one
redirects back with a code, `/auth/callback` exchanges it, and the browser
leaves holding a session cookie. The same routes work unchanged against a real
provider: only the issuer differs.

### The Personas Are A Fixture

The list is static and written by hand. That is the point of it.

A persona carries what an identity server knows: a subject, a name, an email,
and any roles it issues. It carries nothing about your application, because an
identity server has no concept of your organizations, workspaces or permissions.
Those are rows your service owns, read per request, and a token that carried
them would keep asserting a membership after it was revoked.

So the subject is the part that matters. It is the only thing your service sees
of a person, which makes it the join between the two halves of a local setup:

- the persona list here decides who can sign in
- your own fixtures decide what that subject can reach

Both have to name the same ids. Two lists that drift fail silently, because a
token for somebody your service has never seen looks exactly like a new signup
rather than a mistake. Generating one list from the other is the way to stop
that, and if your seed data already defines the people, build the personas from
it rather than writing them twice.

Pick the subjects to cover the cases that are awkward to reach by clicking: the
account with nothing, the one whose access was revoked, the administrator. A
persona list is most useful when it is the failure paths rather than the happy
one.

### What It Does Not Do

The provider issues no refresh token, so a refresh grant is refused rather than
answered. Nothing here exercises rotation, and a client that depends on it
should be tested against a real provider.

Codes are single use and expire, as a real provider's do. Sessions are held in
memory, so a restart signs everybody out.

## Signing Keys

By default the provider generates an ES256 key at import. It lives in memory and
changes on every restart, so nothing has to be created or cleaned up, and a
restart invalidates every token it issued. That is usually what a developer
wants.

Where it is not, supply a key and tokens survive a restart:

```bash
uv run python -m oidcutils.idp --signing-key key.json
```

Or through the environment, which is easier in compose:

```bash
OIDC_DEV_SIGNING_KEY=/run/secrets/dev-key.json
```

An explicit `--signing-key` wins over the variable. Both accept a file path or
the key's own text, in either JWK or PEM form, so a key from `openssl` works as
well as one from this library. A JWK set is accepted and its first key used,
which is the shape a provider exports.

The algorithm follows the key rather than being configured: an EC key signs
ES256, ES384 or ES512 by its curve, and an RSA key signs RS256. A key and an
algorithm that disagree would produce tokens nothing can verify.

Generate one to commit as a fixture:

```python
import json

from joserfc.jwk import ECKey

key = ECKey.generate_key("P-256")
print(json.dumps(key.as_dict(private=True)))
```

!!! danger "Not a production key" A committed signing key is a key everybody
has. It exists so a test can assert against a known token, and it must never be
one a real issuer uses.

## Key Rotation

Restart the server to generate a new signing key, unless one was supplied. The
SDK detects the unknown `kid` and refreshes its JWKS cache automatically.
