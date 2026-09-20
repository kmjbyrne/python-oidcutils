"""The dev provider's authorization page, and a browser login against it.

Before this the provider minted tokens and served no authorization page, so
``create_auth_router`` had nothing to redirect to and a local stack could not
exercise the flow it will take in production. These cover that path end to end.
"""

import re

import httpx
import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from oidcutils import OIDCClient, Principal
from oidcutils.contrib.fastapi import (
    FastAPIAuth,
    create_auth_router,
    create_dev_router,
    current_user,
)
from oidcutils.dev import DevPersona

ISSUER = "http://testserver"
AUDIENCE = "my-api"

PERSONAS = (
    DevPersona(
        key="alice",
        subject="u-alice",
        name="Alice Admin",
        email="alice@acme.example",
        purpose="Owns Acme",
        roles=("admin",),
    ),
    DevPersona(key="bob", subject="u-bob", name="Bob Editor", purpose="Member of Acme"),
)


@pytest.fixture
def provider() -> FastAPI:
    app = FastAPI()
    app.include_router(create_dev_router(ISSUER, AUDIENCE, personas=PERSONAS))
    return app


@pytest.fixture
def client(provider: FastAPI) -> TestClient:
    return TestClient(provider)


def _pick(html: str) -> str:
    """Return the query string behind the first persona link."""
    return re.search(r'href="\?([^"]+)"', html).group(1).replace("&amp;", "&")


class TestAuthorizationPage:
    def test_it_offers_every_persona(self, client: TestClient) -> None:
        page = client.get("/dev/authorize", params={"redirect_uri": "http://app/cb"}).text

        assert "Alice Admin" in page
        assert "Bob Editor" in page

    def test_picking_one_redirects_with_a_code(self, client: TestClient) -> None:
        response = client.get(
            "/dev/authorize",
            params={"redirect_uri": "http://app/cb", "persona": "alice"},
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert "code=" in response.headers["location"]

    def test_it_carries_the_state_back(self, client: TestClient) -> None:
        """The client compares it, and a login that drops it is refused."""
        response = client.get(
            "/dev/authorize",
            params={"redirect_uri": "http://app/cb", "persona": "alice", "state": "xyz"},
            follow_redirects=False,
        )

        assert "state=xyz" in response.headers["location"]

    def test_an_unknown_persona_is_refused(self, client: TestClient) -> None:
        response = client.get(
            "/dev/authorize",
            params={"redirect_uri": "http://app/cb", "persona": "nobody"},
            follow_redirects=False,
        )

        assert response.status_code == 400

    def test_without_personas_there_is_no_page(self) -> None:
        """A provider told about nobody cannot offer anybody, and says so."""
        app = FastAPI()
        app.include_router(create_dev_router(ISSUER, AUDIENCE))

        response = TestClient(app).get("/dev/authorize", params={"redirect_uri": "http://app/cb"})

        assert response.status_code == 404

    def test_discovery_points_at_the_page(self, client: TestClient) -> None:
        """A client reads the endpoint from here rather than being told it."""
        document = client.get("/.well-known/openid-configuration").json()

        assert document["authorization_endpoint"] == f"{ISSUER}/dev/authorize"


class TestCodeExchange:
    def _code(self, client: TestClient) -> str:
        response = client.get(
            "/dev/authorize",
            params={"redirect_uri": "http://app/cb", "persona": "alice"},
            follow_redirects=False,
        )
        return response.headers["location"].split("code=")[1].split("&")[0]

    def test_a_code_becomes_a_token(self, client: TestClient) -> None:
        code = self._code(client)

        response = client.post(
            "/dev/token",
            data={"grant_type": "authorization_code", "code": code, "client_id": "x"},
        )

        assert response.status_code == 200
        assert "access_token" in response.json()

    def test_a_code_is_single_use(self, client: TestClient) -> None:
        """A real provider reads a second presentation as theft."""
        code = self._code(client)
        client.post("/dev/token", data={"grant_type": "authorization_code", "code": code})

        again = client.post("/dev/token", data={"grant_type": "authorization_code", "code": code})

        assert again.status_code == 400

    def test_an_unknown_code_is_refused(self, client: TestClient) -> None:
        response = client.post(
            "/dev/token", data={"grant_type": "authorization_code", "code": "invented"}
        )

        assert response.status_code == 400

    def test_an_unsupported_grant_says_so(self, client: TestClient) -> None:
        """Rather than answering with a token and implying rotation works."""
        response = client.post(
            "/dev/token", data={"grant_type": "refresh_token", "refresh_token": "x"}
        )

        assert response.status_code == 400

    def test_minting_from_json_still_works(self, client: TestClient) -> None:
        """The path a test takes, which needs no browser and no code."""
        response = client.post("/dev/token", json={"subject": "direct"})

        assert response.status_code == 200
        assert "access_token" in response.json()


class TestBrowserLogin:
    """The whole flow, as create_auth_router drives it."""

    @pytest.fixture
    def app(self, provider: FastAPI) -> FastAPI:
        transport = httpx.ASGITransport(app=provider)
        http = httpx.AsyncClient(transport=transport, base_url=ISSUER)
        client = OIDCClient(
            issuer=ISSUER,
            client_id="my-app",
            client_secret="secret",
            redirect_uri=f"{ISSUER}/auth/callback",
            http_client=http,
        )
        provider.include_router(create_auth_router(client), prefix="/auth")
        return provider

    def test_a_login_ends_holding_a_session(self, app: FastAPI) -> None:
        client = TestClient(app)

        start = client.get("/auth/login", follow_redirects=False)
        page = client.get(start.headers["location"].replace(ISSUER, ""), follow_redirects=False)
        picked = client.get(f"/dev/authorize?{_pick(page.text)}", follow_redirects=False)
        done = client.get(picked.headers["location"].replace(ISSUER, ""), follow_redirects=False)

        assert done.status_code == 307
        assert "session_id" in done.headers.get("set-cookie", "")

    def test_the_login_redirect_reaches_the_provider(self, app: FastAPI) -> None:
        start = TestClient(app).get("/auth/login", follow_redirects=False)

        assert "/dev/authorize" in start.headers["location"]


class TestMountDev:
    """One call for a local sign-in, rather than the wiring it replaces."""

    @pytest.fixture
    def app(self) -> FastAPI:
        app = FastAPI()
        FastAPIAuth.mount_dev(app, ISSUER, AUDIENCE, PERSONAS)
        return app

    def test_it_mounts_the_whole_flow(self, app: FastAPI) -> None:
        paths = set(app.openapi()["paths"])

        assert {"/auth/login", "/auth/callback", "/dev/authorize", "/dev/token"} <= paths

    def test_a_login_ends_holding_a_session(self, app: FastAPI) -> None:
        client = TestClient(app)

        start = client.get("/auth/login", follow_redirects=False)
        page = client.get(start.headers["location"].replace(ISSUER, ""), follow_redirects=False)
        picked = client.get(f"/dev/authorize?{_pick(page.text)}", follow_redirects=False)
        done = client.get(picked.headers["location"].replace(ISSUER, ""), follow_redirects=False)

        assert done.status_code == 307
        assert "session_id" in done.headers.get("set-cookie", "")

    def test_the_token_it_issues_validates(self, app: FastAPI) -> None:
        """The validator it returns accepts what the provider it mounted minted."""
        client = TestClient(app)
        token = client.post("/dev/token", json={"subject": "u-alice"}).json()["access_token"]

        @app.get("/who")
        async def who(user: Principal = Depends(current_user)) -> dict[str, str]:
            return {"subject": user.subject}

        response = client.get("/who", headers={"Authorization": f"Bearer {token}"})

        assert response.status_code == 200
        assert response.json() == {"subject": "u-alice"}

    def test_it_binds_the_validator_to_app_state(self, app: FastAPI) -> None:
        assert isinstance(app.state.auth, FastAPIAuth)


class TestSessionCookie:
    """What the cookie the callback sets is worth on an API route."""

    @pytest.fixture
    def app(self) -> FastAPI:
        app = FastAPI()
        FastAPIAuth.mount_dev(app, ISSUER, AUDIENCE, PERSONAS)

        @app.get("/who")
        async def who(user: Principal = Depends(current_user)) -> dict[str, str]:
            return {"subject": user.subject}

        return app

    def _sign_in(self, client: TestClient) -> None:
        start = client.get("/auth/login", follow_redirects=False)
        page = client.get(start.headers["location"].replace(ISSUER, ""), follow_redirects=False)
        picked = client.get(f"/dev/authorize?{_pick(page.text)}", follow_redirects=False)
        client.get(picked.headers["location"].replace(ISSUER, ""), follow_redirects=False)

    def test_a_signed_in_browser_reaches_a_guarded_route(self, app: FastAPI) -> None:
        """The whole point: a login that leaves the caller able to call things."""
        client = TestClient(app)
        self._sign_in(client)

        response = client.get("/who")

        assert response.status_code == 200
        assert response.json() == {"subject": PERSONAS[0].subject}

    def test_without_a_cookie_it_refuses(self, app: FastAPI) -> None:
        assert TestClient(app).get("/who").status_code == 401

    def test_an_unknown_session_refuses(self, app: FastAPI) -> None:
        client = TestClient(app)
        client.cookies.set("session_id", "invented")

        assert client.get("/who").status_code == 401

    def test_a_bearer_token_still_works(self, app: FastAPI) -> None:
        """An application with a sign-in page is still callable by a script."""
        client = TestClient(app)
        token = client.post("/dev/token", json={"subject": "u-script"}).json()["access_token"]

        response = client.get("/who", headers={"Authorization": f"Bearer {token}"})

        assert response.json() == {"subject": "u-script"}
