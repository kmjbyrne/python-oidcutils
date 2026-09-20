# Changelog

Written by hand, in the shape [Keep a Changelog](https://keepachangelog.com)
describes. Versions follow [semantic versioning](https://semver.org): this is a
library other projects pin, so a major number promising a breaking change is a
promise somebody relies on.

Entries before `0.0.1-beta` were reconstructed from the commit history after the
fact, so they say what changed rather than what was announced at the time.

## 0.0.3-beta - 2026-09-20

### Added

- `session_principal` turns the session cookie `create_auth_router` sets back
  into a `Principal`, refreshing the access token where it is near expiry. A
  bearer token is served from the header where one is sent, so an application
  with a sign-in page is still callable by a script. `create_auth_router` now
  exposes its token manager and cookie name, which were closed over and
  unreachable.
- `FastAPIAuth.mount_dev` gives an app a working browser login against an
  in-process provider in one call: the provider, an authorization page listing
  personas, the `/login` and `/callback` routes, and a validator bound to accept
  what comes out of it. It exists because wiring that by hand needs a transport
  that cannot be built until the app it wraps exists.
- The dev identity provider serves an authorization page. Given `personas`,
  `create_dev_router` mounts `/dev/authorize`: it lists them, picking one
  redirects back with a single-use code, and `/dev/token` exchanges it for a
  signed token.
- `DevPersona` describes somebody the page offers to sign in as: subject, name,
  email, and any roles the identity server issues. Not memberships, which are
  the application's own concept.

### Fixed

- `OIDCClient` now carries its `http_client`'s transport into the token endpoint
  calls. It was used for discovery only, so `exchange_code` and `refresh` always
  went to the network: against a mounted dev provider, discovery succeeded and
  the exchange then failed trying to resolve the issuer as a hostname.
- The discovery document advertised `/authorize`, which nothing served. It now
  names `/dev/authorize`, which does exist.
- The IdP tests run in a second rather than ten. `serve_forever` polls, and
  `shutdown()` waits for the next poll, so every test in the module paid the
  default half-second interval in teardown.
- The dev token endpoint reads a form-encoded grant without `python-multipart`.
  `request.form()` needs that package, which this library does not declare, so a
  code exchange failed for anyone who had installed only its own dependencies.

### Documentation

- `create_auth_router` is documented. It provides `/login` and `/callback` for
  the authorization code flow and appeared in no guide or reference, so the
  library read as though it could validate tokens but not sign anybody in.
- A "Two Halves" section separates the resource server from the client, because
  the FastAPI section covered only the first and did not say so.
- The token refresh example no longer begins mid-flow with an undefined `code`.
- The dev identity provider's limitation is stated: it mints tokens and serves
  no authorization page, so `create_auth_router` has nothing to redirect to
  locally. Its discovery document advertises an `authorization_endpoint` that is
  not served.
- `get_access_token` is documented as not single-flighting its refresh, which
  matters against a provider that rotates refresh tokens and treats reuse as
  theft.
- Fixed the README link to the FastAPI guide, which dropped the `guide/` segment
  and pointed at a file that does not exist.

## 0.0.2-beta - 2026-09-20

### Fixed

- A token whose algorithm is not in the accepted list now answers `401` rather
  than raising out of `validate_token` as an unhandled error. The token was
  always rejected; the fault was which exception left the method, which let an
  unauthenticated caller raise one on every request and told them "algorithm not
  permitted" apart from "signature bad". Caught by `JoseError` rather than by
  name, so a future error class in `joserfc` cannot escape the same way.

## 0.0.1-beta - 2026-09-19

The first tagged release. An OAuth2/OIDC resource server SDK: validate a bearer
token against a provider's JWKS, map its claims to a `Principal`, and guard
FastAPI routes by role or permission.

### Added

- `TokenValidator`, which fetches a provider's discovery document and JWKS,
  verifies signature, `iss`, `aud` and expiry, and caches the key set with a
  refresh on signature failure so a rotation costs one retry rather than a fetch
  per request.
- `Principal` and `ClaimMapper`, turning a validated token's claims into
  subject, issuer, email, name, tenant, roles and permissions.
- `FastAPIAuth`, with `current_user`, `require_role` and `require_permission`.
- A development identity provider, so a local run needs no external one. It runs
  three ways: `python -m oidcutils.idp` as its own process, `create_dev_idp` as
  an app to mount where a second process is unwelcome, and `dev_auth` for a
  mounted provider that is not listening on a port.

### Changed

- `FastAPIAuth` takes its configuration in the constructor, and `from_settings`
  takes an `OIDCSettings`.
- `require_role` and `require_permission` take an optional `user_dependency`,
  defaulting to `current_user`. Without it they closed over `current_user` and
  resolved `app.state.auth` while the routes resolved the app's own dependency,
  so an app using dependency overrides had principals with the right role
  rejected.

### Breaking

- `current_user` raises `RuntimeError` when no `FastAPIAuth` is configured. It
  previously returned an anonymous `Principal`, so an unwired app served 200 on
  open routes and 403 on guarded ones and never 401, which made a wiring mistake
  look like working authorization.
