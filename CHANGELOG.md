# Changelog

Written by hand, in the shape [Keep a Changelog](https://keepachangelog.com)
describes. Versions follow [semantic versioning](https://semver.org): this is a
library other projects pin, so a major number promising a breaking change is a
promise somebody relies on.

Entries before `0.0.1-beta` were reconstructed from the commit history after the
fact, so they say what changed rather than what was announced at the time.

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
