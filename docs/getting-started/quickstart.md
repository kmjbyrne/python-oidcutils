# Quick Start

This guide walks through validating a JWT access token and extracting user
identity. No framework required.

## Validate a Token

```python
from oidcutils import TokenValidator, Principal

validator = TokenValidator(
    issuer="https://id.example.com",
    audience="my-api",
)

principal: Principal = await validator.validate_token(token)
```

The validator:

1. Fetches the OIDC discovery document from
   `{issuer}/.well-known/openid-configuration`
2. Downloads the JWKS from the discovered `jwks_uri`
3. Verifies the token signature, expiry, issuer, and audience
4. Maps claims into a `Principal`

JWKS are cached. Subsequent calls skip the HTTP requests unless the token was
signed by an unknown key (which triggers a single JWKS refresh for key
rotation).

## Use The Principal

```python
principal.subject  # "user-123"
principal.email  # "user@example.com"
principal.roles  # frozenset({"admin", "viewer"})
principal.permissions  # frozenset({"orders.read", "orders.write"})

principal.has_role("admin")  # True
principal.has_permission("orders.write")  # True
principal.has_any_role("admin", "editor")  # True
principal.has_all_permissions("orders.read", "orders.write")  # True
```

## Handle Errors

```python
from oidcutils import TokenError

try:
    principal = await validator.validate_token(token)
except TokenError as e:
    # "Token has expired", "Invalid token signature: ...", "Invalid claim: ..."
    print(e)
```

`TokenError` is raised for any validation failure: expired tokens, bad
signatures, wrong issuer/audience, or missing required claims.

Reaching the issuer is a separate concern. Discovery and JWKS are fetched over
HTTP, and a transport failure -- an unreachable issuer, a timeout, a 5xx from
the provider -- raises the underlying `httpx` error rather than `TokenError`.
Catch `httpx.HTTPError` alongside it if the caller must stay up while the
provider is down:

```python
import httpx

try:
    principal = await validator.validate_token(token)
except TokenError:
    ...  # the token is bad: reject the caller
except httpx.HTTPError:
    ...  # the provider is unreachable: the token may well be fine
```

Under the FastAPI integration this distinction shows up as status codes.
`TokenError` becomes a 401; a transport failure propagates and becomes a 500.

## Next Steps

- [FastAPI Integration](../guide/fastapi-integration.md) -- check tokens in
  routes, for a service that receives them
- [Connecting An IdP](../guide/connecting-an-idp.md) -- sign a browser in, for a
  service that needs to obtain them
- [Token Refresh](../guide/token-refresh.md) -- manage token lifecycle
- [Claim Mapping](../guide/claim-mapping.md) -- customize how claims become a
  Principal
