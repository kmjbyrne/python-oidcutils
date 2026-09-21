import secrets
from collections.abc import Callable
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, quote

import httpx
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from oidcutils.dev import DevPersona

from oidcutils.claims import ClaimMapper
from oidcutils.client import OIDCClient
from oidcutils.principal import Principal
from oidcutils.resource import TokenError, TokenValidator
from oidcutils.tokens import InMemoryTokenStore, TokenManager


class OIDCSettings:
    """Mixin for pydantic-settings classes. Add to your Settings to get OIDC fields."""

    OIDC_ISSUER: str = ""
    OIDC_AUDIENCE: str = ""
    OIDC_CLIENT_ID: str = ""
    OIDC_CLIENT_SECRET: str = ""
    OIDC_REDIRECT_URI: str = ""
    OIDC_BYPASS: bool = False


_bearer_scheme = HTTPBearer(auto_error=True)

DEFAULT_AUTH_PREFIX = "/auth"
DEFAULT_LOGIN_PATH = "/login"
DEFAULT_LOGIN_URI = f"{DEFAULT_AUTH_PREFIX}{DEFAULT_LOGIN_PATH}"


class FastAPIAuth:
    def __init__(
        self,
        issuer: str,
        audience: str,
        *,
        auth_prefix: str = DEFAULT_AUTH_PREFIX,
        login_path: str = DEFAULT_LOGIN_PATH,
        algorithms: list[str] | None = None,
        claim_mapper: ClaimMapper | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        """Build auth against ``issuer``.

        ``http_client`` is the client used to fetch discovery and JWKS. Pass one
        to reach an issuer that is not on the network: an in-process dev IdP is
        mounted rather than listening on a port, so it is reached with an
        ``httpx.ASGITransport`` rather than a socket.
        """
        self.auth_prefix = auth_prefix
        self.login_path = login_path
        self.login_uri = f"{auth_prefix}{login_path}"
        self._validator = TokenValidator(
            issuer=issuer,
            audience=audience,
            algorithms=algorithms,
            claim_mapper=claim_mapper,
            http_client=http_client,
        )

    @classmethod
    def from_settings(cls, settings: OIDCSettings, **kwargs: Any) -> "FastAPIAuth":
        return cls(
            issuer=settings.OIDC_ISSUER,
            audience=settings.OIDC_AUDIENCE,
            **kwargs,
        )

    @classmethod
    def mount_dev(
        cls,
        app: FastAPI,
        issuer: str,
        audience: str,
        personas: "Sequence[DevPersona]",
        *,
        client_id: str = "dev-client",
        client_secret: str = "",
        auth_prefix: str = "/auth",
        post_login_redirect: str = "/",
    ) -> "FastAPIAuth":
        """Give ``app`` a working browser login against an in-process provider.

        Everything a local sign-in needs, in one call: the provider that issues
        tokens, an authorization page listing ``personas``, the ``/login`` and
        ``/callback`` routes that drive the flow, and a validator that accepts
        what comes out of it. Bound to ``app.state.auth`` and returned.

        The plumbing it absorbs is the reason it exists. A provider mounted in
        the application it serves listens on no port, so the sign-in flow and
        the validator both have to reach it over ASGI rather than by resolving
        ``issuer`` as a hostname, and the transport cannot be built until the
        app it wraps exists.

        ``issuer`` must be the address the app answers on, because the redirect
        sends a browser there::

            auth = FastAPIAuth.mount_dev(app, issuer, audience, personas)
            app.dependency_overrides[current_user] = auth.get_principal

        Development only. It signs tokens for people who do not exist and
        offers them to anybody who loads the page.
        """
        transport = _DeferredASGITransport(app)
        http_client = httpx.AsyncClient(transport=transport, base_url=issuer)
        # Generated rather than defaulted to a literal. The provider checks
        # nothing, so the value is arbitrary, and a constant written here is
        # one somebody copies into a deployment because it looked like
        # configuration.
        secret = client_secret or secrets.token_urlsafe(16)

        app.include_router(create_dev_router(issuer, audience, personas=personas))

        client = OIDCClient(
            issuer=issuer,
            client_id=client_id,
            client_secret=secret,
            redirect_uri=f"{issuer.rstrip('/')}{auth_prefix}/callback",
            http_client=http_client,
        )
        router = create_auth_router(client, post_login_redirect=post_login_redirect)
        app.include_router(router, prefix=auth_prefix)

        auth = cls(issuer=issuer, audience=audience, http_client=http_client)
        app.state.auth = auth

        # The last step, and the one that is easy to leave out: a browser
        # arrives holding the cookie the callback set, and the routes want a
        # bearer token. Bound here so a login actually signs somebody in
        # rather than producing a cookie nothing reads.
        app.dependency_overrides[current_user] = session_principal(
            auth, router.token_manager, session_key=router.session_key
        )
        return auth

    async def get_principal(
        self,
        credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
    ) -> Principal:
        try:
            return await self._validator.validate_token(credentials.credentials)
        except TokenError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc


def configure(app: FastAPI, settings: OIDCSettings, **kwargs: Any) -> FastAPIAuth | None:
    """Wire OIDC auth into a FastAPI app from settings.

    When OIDC_BYPASS is True, mounts a built-in dev IdP with discovery, JWKS,
    and a POST /dev/token endpoint. No external provider needed.
    """
    if settings.OIDC_BYPASS:
        configure_dev(app, settings)
        return app.state.auth  # type: ignore[no-any-return]
    auth = FastAPIAuth.from_settings(settings, **kwargs)
    app.state.auth = auth
    return auth


def _get_auth(request: Request) -> FastAPIAuth | None:
    return getattr(request.app.state, "auth", None)


async def current_user(
    auth: FastAPIAuth | None = Depends(_get_auth),
    credentials: HTTPAuthorizationCredentials | None = Depends(HTTPBearer(auto_error=False)),
) -> Principal:
    """Resolve the caller's Principal from the bearer token.

    Raises RuntimeError when no auth is configured. Returning an anonymous
    principal instead would let an unwired app serve protected routes.
    """
    if auth is None:
        raise RuntimeError(
            "No FastAPIAuth configured. Set app.state.auth in your application "
            "factory, or override the current_user dependency."
        )
    if credentials is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return await auth.get_principal(credentials)


def require_role(
    role: str,
    user_dependency: Callable[..., Any] = current_user,
) -> Callable[..., Any]:
    """Build a dependency admitting only callers holding ``role``.

    ``user_dependency`` resolves the Principal. Override it when the app
    supplies its own instead of reading ``app.state.auth``.
    """

    async def dependency(
        user: Principal = Depends(user_dependency),
    ) -> Principal:
        if not user.has_role(role):
            raise HTTPException(
                status_code=403,
                detail=f"Required role: {role}",
            )
        return user

    return dependency


def require_permission(
    permission: str,
    user_dependency: Callable[..., Any] = current_user,
) -> Callable[..., Any]:
    """Build a dependency admitting only callers holding ``permission``.

    ``user_dependency`` resolves the Principal. Override it when the app
    supplies its own instead of reading ``app.state.auth``.
    """

    async def dependency(
        user: Principal = Depends(user_dependency),
    ) -> Principal:
        if not user.has_permission(permission):
            raise HTTPException(
                status_code=403,
                detail=f"Required permission: {permission}",
            )
        return user

    return dependency


def create_auth_router(
    client: OIDCClient,
    token_manager: TokenManager | None = None,
    login_path: str | None = "/login",
    callback_path: str | None = "/callback",
    post_login_redirect: str = "/",
    session_key: str = "session_id",
) -> APIRouter:
    """Create a router with endpoints for the auth code flow.

    The browser never sees client credentials or tokens. It only follows
    redirects and receives a session cookie.

    Pass ``None`` for ``login_path`` or ``callback_path`` to omit that route,
    for services that only need one half of the flow.
    """
    store = InMemoryTokenStore()
    manager = token_manager or TokenManager(client=client, store=store)
    _pending_states: dict[str, str] = {}

    router = APIRouter()

    if login_path is not None:

        @router.get(login_path)
        async def login(request: Request) -> RedirectResponse:
            url, state = await client.authorization_url()
            _pending_states[state] = post_login_redirect
            return RedirectResponse(url)

    if callback_path is not None:

        @router.get(callback_path)
        async def callback(request: Request, code: str, state: str) -> RedirectResponse:
            if state not in _pending_states:
                raise HTTPException(400, "Invalid or expired state parameter")

            redirect_to = _pending_states.pop(state)

            token_set = await client.exchange_code(code)

            sid = secrets.token_urlsafe(32)
            await manager.store_token(sid, token_set)

            response = RedirectResponse(redirect_to)
            response.set_cookie(
                key=session_key,
                value=sid,
                httponly=True,
                secure=request.url.scheme == "https",
                samesite="lax",
            )
            return response

    router.token_manager = manager  # type: ignore[attr-defined]
    router.session_key = session_key  # type: ignore[attr-defined]
    return router


def session_principal(
    auth: FastAPIAuth,
    token_manager: TokenManager,
    session_key: str = "session_id",
) -> Callable[..., Any]:
    """Build a dependency resolving a session cookie to a ``Principal``.

    ``create_auth_router`` leaves the browser holding an httpOnly cookie
    naming a session, and the API routes behind ``current_user`` want a bearer
    token. This is the step between: read the cookie, exchange it for the
    access token stored against it, and validate that.

    A caller sending a bearer token is served from the header instead, so an
    application with a sign-in page is still callable by a script.

    The token is refreshed on the way through if it is near expiry, so a long
    session does not start failing mid-visit.

    Bind it where the routes look for their caller::

        router = create_auth_router(client)
        app.include_router(router, prefix="/auth")
        app.dependency_overrides[current_user] = session_principal(
            auth, router.token_manager
        )
    """

    async def dependency(request: Request) -> Principal:
        # A bearer token wins where one is sent. The two callers differ: a
        # browser holds a cookie because it cannot be trusted with a token,
        # and a script sends a token because it has no cookie jar. Refusing
        # the header would mean a service that signs people in cannot also be
        # called by anything else.
        header = request.headers.get("authorization", "")
        if header.lower().startswith("bearer "):
            return await auth.get_principal(
                HTTPAuthorizationCredentials(scheme="Bearer", credentials=header[7:])
            )

        sid = request.cookies.get(session_key)
        if not sid:
            raise HTTPException(status_code=401, detail="Not authenticated")

        try:
            access_token = await token_manager.get_access_token(sid)
        except (LookupError, ValueError) as exc:
            # No session stored, or one whose refresh token is gone. Both mean
            # the same thing to a caller: sign in again.
            raise HTTPException(status_code=401, detail="Session expired") from exc

        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=access_token)
        return await auth.get_principal(credentials)

    return dependency


def create_dev_router(
    issuer: str,
    audience: str,
    prefix: str = "/dev",
    personas: "Sequence[DevPersona] | None" = None,
) -> APIRouter:
    """Mount discovery, JWKS, token minting and an authorization page.

    ``personas`` are who the authorization page offers to sign in as. Given
    any, the provider can complete a browser code flow: the page lists them,
    picking one redirects back with a code, and the token endpoint exchanges
    it. Without them the page has nobody to offer and answers 404, and the
    provider mints tokens directly as it always has.
    """
    from oidcutils.dev import (
        DevPersona,
        discovery_document,
        issue_code,
        mint_token,
        public_jwks,
        redeem_code,
    )

    offered: dict[str, DevPersona] = {p.key: p for p in personas or ()}

    router = APIRouter()

    @router.get("/.well-known/openid-configuration")
    async def discovery() -> dict[str, Any]:
        return discovery_document(issuer)

    @router.get("/.well-known/jwks.json")
    async def jwks() -> dict[str, Any]:
        return public_jwks()

    @router.get(f"{prefix}/authorize", response_class=HTMLResponse)
    async def authorize(redirect_uri: str, state: str = "", persona: str = "") -> Any:
        """Offer the personas, or redirect back with a code for the one picked.

        Two jobs in one endpoint because that is what an authorization endpoint
        is: the browser arrives, somebody proves who they are, and the browser
        leaves carrying a code. Proving it here means clicking a name.
        """
        if not offered:
            raise HTTPException(
                404,
                "No personas configured. Pass personas= to create_dev_router "
                "to serve an authorization page.",
            )

        if persona:
            chosen = offered.get(persona)
            if chosen is None:
                raise HTTPException(400, f"Unknown persona: {persona}")
            code = issue_code(chosen, redirect_uri)
            separator = "&" if "?" in redirect_uri else "?"
            location = f"{redirect_uri}{separator}code={code}"
            if state:
                location = f"{location}&state={state}"
            return RedirectResponse(location, status_code=303)

        return HTMLResponse(_persona_page(offered.values(), redirect_uri, state))

    @router.post(f"{prefix}/token")
    async def dev_token(request: Request) -> dict[str, Any]:
        """Mint a token, from a code or from claims given directly.

        Two shapes, because two callers. An OAuth2 client posts a form carrying
        a code, which is the path a browser login takes. A test posts JSON
        saying who to be, which needs no browser and no code.
        """
        content_type = request.headers.get("content-type", "")

        if "application/x-www-form-urlencoded" in content_type:
            # Parsed here rather than with request.form(), which needs
            # python-multipart. That dependency exists for file uploads, and
            # pulling it in so a dev provider can read four fields would put
            # it in every consumer's environment.
            form = {
                key: value[0] for key, value in parse_qs((await request.body()).decode()).items()
            }
            grant = form.get("grant_type", "")

            if grant == "authorization_code":
                claims = redeem_code(form.get("code", ""))
                if claims is None:
                    raise HTTPException(400, "Invalid or expired authorization code")
                return mint_token(
                    issuer=issuer,
                    audience=audience,
                    subject=claims["subject"],
                    name=claims["name"],
                    email=claims["email"],
                    roles=claims["roles"],
                    permissions=claims["permissions"],
                )

            # A refresh grant. The dev provider issues no refresh tokens, so
            # this says so rather than answering with a token that would make a
            # client believe rotation is being exercised.
            raise HTTPException(400, f"Unsupported grant_type: {grant}")

        body = await request.json() if await request.body() else {}
        return mint_token(issuer=issuer, audience=audience, **body)

    return router


def _persona_page(personas: "Iterable[DevPersona]", redirect_uri: str, state: str) -> str:
    """Return the authorization page: a list of people to sign in as.

    Deliberately plain. It stands in for a real sign-in screen and is only ever
    seen by somebody running the stack locally, so it carries no styling worth
    maintaining and no JavaScript at all.
    """
    from html import escape

    rows = []
    for persona in personas:
        query = f"redirect_uri={quote(redirect_uri)}&persona={quote(persona.key)}"
        if state:
            query = f"{query}&state={quote(state)}"
        subtitle = persona.purpose or persona.email or persona.subject
        rows.append(
            f'<li><a href="?{query}">'
            f"<strong>{escape(persona.name or persona.key)}</strong>"
            f"<span>{escape(subtitle)}</span></a></li>"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Sign in</title>
<style>
  body {{ font: 16px system-ui, sans-serif; margin: 0; padding: 3rem 1rem;
         background: #14161a; color: #e6e8eb; }}
  main {{ max-width: 26rem; margin: 0 auto; }}
  h1 {{ font-size: 1.25rem; margin: 0 0 .25rem; }}
  p.lede {{ margin: 0 0 1.5rem; color: #9aa3ad; font-size: .875rem; }}
  ul {{ list-style: none; margin: 0; padding: 0; }}
  li {{ margin-bottom: .5rem; }}
  a {{ display: block; padding: .75rem 1rem; border: 1px solid #2a2f36;
       border-radius: .5rem; text-decoration: none; color: inherit; }}
  a:hover {{ border-color: #4a90d9; background: #1a1d22; }}
  strong {{ display: block; font-weight: 600; }}
  span {{ display: block; color: #9aa3ad; font-size: .8125rem; margin-top: .125rem; }}
</style>
</head>
<body>
<main>
  <h1>Sign in</h1>
  <p class="lede">Development identity provider. Pick somebody to be.</p>
  <ul>{"".join(rows)}</ul>
</main>
</body>
</html>"""


def create_dev_idp(issuer: str, audience: str) -> FastAPI:
    """Return a standalone app serving discovery, JWKS and token minting.

    An app of its own rather than routes added to yours. That keeps the issuer
    a separate thing from the application validating against it, so the app
    makes an ordinary outward request for a key instead of calling itself.

    Run it on its own port, or mount it in-process during development::

        idp = create_dev_idp(issuer="http://localhost:8000/idp", audience="my-api")
        app.mount("/idp", idp)

    ``issuer`` must be the address the IdP answers on, mount path included, so
    that the discovery document points at endpoints a client can actually
    reach. Mounted in-process there is no port to reach it on, so the validator
    needs an ``httpx.ASGITransport`` client: see :func:`dev_auth`.

    It signs with an ephemeral key generated at import and mints a token for
    anybody who asks, so it has no business anywhere but a developer's machine.
    """
    idp = FastAPI(title="Development IdP", docs_url=None, redoc_url=None)
    idp.include_router(create_dev_router(issuer=issuer, audience=audience))
    return idp


def dev_auth(app: FastAPI, issuer: str, audience: str) -> FastAPIAuth:
    """Return auth that reaches an in-process IdP rather than the network.

    ``app`` is whatever the IdP is reachable through: the mounted parent, or
    the IdP itself. Requests for discovery and JWKS are handed straight to it,
    because an app mounted in another process is not listening on a port and a
    test has no server at all.
    """
    return FastAPIAuth(
        issuer=issuer,
        audience=audience,
        http_client=httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=issuer),
    )


def configure_dev(app: FastAPI, settings: OIDCSettings) -> None:
    """Set up auth with a built-in dev IdP. No external provider needed."""
    issuer = settings.OIDC_ISSUER or "http://localhost:8000"
    audience = settings.OIDC_AUDIENCE or "dev"

    app.include_router(create_dev_router(issuer=issuer, audience=audience))

    app.state.auth = FastAPIAuth(issuer=issuer, audience=audience)


class AuthenticateHeaderMiddleware(BaseHTTPMiddleware):
    """Adds a ``WWW-Authenticate`` header to 401 responses.

    Usage::

        app.add_middleware(AuthenticateHeaderMiddleware, login_uri="/auth/login")
    """

    def __init__(self, app: Any, login_uri: str = DEFAULT_LOGIN_URI, realm: str = "api") -> None:
        super().__init__(app)
        self._header_value = f'Bearer realm="{realm}", login_uri="{login_uri}"'

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        if response.status_code == 401:
            response.headers["WWW-Authenticate"] = self._header_value
        return response


class _DeferredASGITransport(httpx.AsyncBaseTransport):
    """Hands requests to an app that is still being built.

    The transport needs the app and the app needs the transport, because the
    provider is mounted inside the thing that calls it. Resolving the app when
    a request is made rather than when the transport is constructed breaks the
    cycle, and by then every route is in place.
    """

    def __init__(self, app: FastAPI) -> None:
        self._app = app

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Pass ``request`` to the app over ASGI."""
        return await httpx.ASGITransport(app=self._app).handle_async_request(request)
