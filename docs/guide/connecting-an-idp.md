# Connecting A FastAPI Service To An Identity Provider

You have a FastAPI service. You have an identity provider running somewhere
else. This page is the wiring between them, for the case where a browser signs
in and then calls your API.

If your service only ever receives bearer tokens that something else obtained,
you do not need any of this. Read
[FastAPI Integration](fastapi-integration.md) instead and stop there.

## The Four Pieces

A sign-in flow needs four things wired, and three of them are easy to find. The
fourth is the one that catches people.

1. A **validator**, which turns a token into a `Principal`.
2. A **client**, which drives the browser to the provider and exchanges the code
   it comes back with.
3. Two **routes**, `/login` and `/callback`.
4. A **join**, because the callback leaves the browser holding a cookie and
   your routes are looking for a bearer token.

Leave out the fourth and a sign-in appears to work: the provider redirects, the
cookie gets set, and then every API call answers 401.

## Configuration

Two addresses, and they are not the same address.

```python
from oidcutils.contrib.fastapi import OIDCSettings
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings, OIDCSettings):
    model_config = SettingsConfigDict(env_file=(".env", ".env.local"))

    # The `redirect_uri` of RFC 6749: the route on YOUR service that the
    # provider sends the browser back to. Declare it yourself; OIDCSettings
    # carries the client credentials but not this.
    #
    # The whole URL, not a base to join onto. Providers compare it as an exact
    # string, so it is the value that has to match what you registered.
    OIDC_REDIRECT_URI: str = "http://localhost:8000/auth/callback"
```

`OIDCSettings` contributes `OIDC_ISSUER`, `OIDC_AUDIENCE`, `OIDC_CLIENT_ID` and
`OIDC_CLIENT_SECRET`. The first two are read by the validator; the last two are
read by the client and ignored by everything else.

```bash
OIDC_ISSUER="http://localhost:9000"        # the provider
OIDC_AUDIENCE="my-api"                     # the `aud` your API accepts
OIDC_CLIENT_ID="my-app"
OIDC_CLIENT_SECRET="secret"
OIDC_REDIRECT_URI="http://localhost:8000/auth/callback"  # your service
```

The issuer is the provider's address. The redirect URI is yours. Deriving one
from the other sends the browser back to the provider, which has no callback
route and answers 404.

## Wiring

```python
from fastapi import FastAPI
from oidcutils import OIDCClient
from oidcutils.contrib.fastapi import (
    FastAPIAuth,
    create_auth_router,
    current_user,
    session_principal,
)

app = FastAPI()

# 1. The validator. current_user reads it off app.state.
auth = FastAPIAuth(
    issuer=settings.OIDC_ISSUER,
    audience=settings.OIDC_AUDIENCE,
)
app.state.auth = auth

# 2. The client. issuer and redirect_uri are separate values: one names the
#    provider, the other names a route on this service.
client = OIDCClient(
    issuer=settings.OIDC_ISSUER,
    client_id=settings.OIDC_CLIENT_ID,
    client_secret=settings.OIDC_CLIENT_SECRET,
    redirect_uri=settings.OIDC_REDIRECT_URI,
)

# 3. The routes.
router = create_auth_router(client, post_login_redirect="/")
app.include_router(router, prefix="/auth")

# 4. The join. Without this the cookie the callback set is a value nothing
#    redeems, and every protected route answers 401 to a signed-in browser.
app.dependency_overrides[current_user] = session_principal(
    auth,
    router.token_manager,
    session_key=router.session_key,
)
```

Routes are unchanged from the resource-server case:

```python
@app.get("/me")
async def me(user: Principal = Depends(current_user)):
    return {"subject": user.subject}


@app.get("/admin")
async def admin(user: Principal = Depends(require_role("admin"))):
    return {"admin": user.subject}
```

Both styles work at once after this. A browser arrives with the session cookie,
a script arrives with an `Authorization` header, and `session_principal` serves
whichever it finds.

## Sessions Beyond One Process

`create_auth_router` defaults to an in-memory `TokenStore`. A restart signs
everybody out and two workers do not share sessions, so anything past a single
process needs a `TokenManager` backed by your own store:

```python
manager = TokenManager(client=client, store=MyRedisStore())
router = create_auth_router(client, token_manager=manager)
```

## When It Does Not Work

| Symptom                               | Cause                                                         |
| ------------------------------------- | ------------------------------------------------------------- |
| 404 at the provider after sign-in     | `redirect_uri` built from the issuer rather than your service |
| 401 on every route, browser signed in | Step 4 missing                                                |
| `Invalid claim: 'aud'`                | The provider mints a different audience than `OIDC_AUDIENCE`  |
| `ConnectError` on `/login`            | The issuer does not resolve from inside your service          |
| `CERTIFICATE_VERIFY_FAILED`           | The issuer is served over TLS your service does not trust     |
| `Issuer mismatch: expected X, got Y`  | Discovery reports a different issuer than configured          |

## A Provider To Develop Against

`FastAPIAuth.mount_dev` mounts a provider inside your own app, which is the
quickest way to click through a login with nothing else running. It derives
`redirect_uri` from the issuer, which is correct only because the provider and
the app are then the same host. Do not reach for it when the provider is a
separate service: that assumption is what produces the 404 in the table above.
