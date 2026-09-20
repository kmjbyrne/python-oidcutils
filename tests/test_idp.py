"""The standalone development IdP.

Run over a real socket on a real port, because that is the point of it: an app
pointed at this fetches keys the way it will fetch them from a real provider.
A test that reached in over ASGI would be testing the mountable variant
instead.
"""

import json
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator

import pytest
from joserfc.jwk import ECKey, RSAKey

from oidcutils.dev import KEY_ENV, load_signing_key, public_jwks, use_signing_key
from oidcutils.idp import serve
from oidcutils.resource import TokenError, TokenValidator

AUDIENCE = "my-api"


@pytest.fixture
def idp() -> Iterator[str]:
    """Run the IdP on a free port and yield the address it answers as."""
    server = serve(port=0, audience=AUDIENCE)
    # serve_forever polls, and shutdown() waits for the next poll to notice.
    # The default interval is half a second, which every test in this module
    # was paying in teardown.
    threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    ).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def _get(url: str) -> dict:
    """Return the JSON body at ``url``."""
    with urllib.request.urlopen(url) as response:
        return json.load(response)


def _post(url: str, body: dict) -> dict:
    """Post ``body`` as JSON and return the response."""
    request = urllib.request.Request(
        url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request) as response:
        return json.load(response)


class TestDiscovery:
    def test_publishes_the_address_it_answers_on(self, idp):
        """A document naming somewhere else sends clients somewhere else."""
        assert _get(f"{idp}/.well-known/openid-configuration")["issuer"] == idp

    def test_points_at_its_own_jwks(self, idp):
        document = _get(f"{idp}/.well-known/openid-configuration")

        assert document["jwks_uri"] == f"{idp}/.well-known/jwks.json"

    def test_names_the_algorithm_it_signs_with(self, idp):
        document = _get(f"{idp}/.well-known/openid-configuration")

        assert document["id_token_signing_alg_values_supported"] == ["ES256"]


class TestKeys:
    def test_serves_a_public_key(self, idp):
        keys = _get(f"{idp}/.well-known/jwks.json")["keys"]

        assert [(k["kty"], k["crv"]) for k in keys] == [("EC", "P-256")]

    def test_the_key_is_for_signing(self, idp):
        [key] = _get(f"{idp}/.well-known/jwks.json")["keys"]

        assert key["use"] == "sig"

    def test_the_private_half_is_not_served(self, idp):
        """The one thing that must never leave the process."""
        [key] = _get(f"{idp}/.well-known/jwks.json")["keys"]

        assert "d" not in key


class TestMinting:
    def test_mints_a_bearer_token(self, idp):
        minted = _post(f"{idp}/dev/token", {})

        assert minted["token_type"] == "Bearer"
        assert minted["access_token"]

    def test_an_empty_body_is_allowed(self, idp):
        """Asking for nothing in particular should still get a token."""
        request = urllib.request.Request(f"{idp}/dev/token", data=b"", method="POST")
        with urllib.request.urlopen(request) as response:
            assert json.load(response)["access_token"]

    def test_a_claim_nobody_recognises_is_refused(self, idp):
        """A typo should be an error rather than a claim silently dropped."""
        with pytest.raises(urllib.error.HTTPError) as refused:
            _post(f"{idp}/dev/token", {"rolls": ["admin"]})

        assert refused.value.code == 400

    def test_a_body_that_is_not_an_object_is_refused(self, idp):
        request = urllib.request.Request(
            f"{idp}/dev/token", data=b"[1, 2]", headers={"Content-Type": "application/json"}
        )
        with pytest.raises(urllib.error.HTTPError) as refused:
            urllib.request.urlopen(request)

        assert refused.value.code == 400


class TestUnknownPaths:
    def test_an_unknown_get_is_not_found(self, idp):
        with pytest.raises(urllib.error.HTTPError) as refused:
            _get(f"{idp}/nothing")

        assert refused.value.code == 404

    def test_an_unknown_post_is_not_found(self, idp):
        with pytest.raises(urllib.error.HTTPError) as refused:
            _post(f"{idp}/nothing", {})

        assert refused.value.code == 404


class TestAgainstTheValidator:
    """The whole point: a token this minted, checked by the real validator.

    Nothing is stubbed. The validator fetches discovery and JWKS over the
    socket and verifies the signature against the key it was given, which is
    the same path it takes against a real provider.
    """

    async def test_a_minted_token_validates(self, idp):
        token = _post(f"{idp}/dev/token", {"subject": "usr_alice"})["access_token"]

        principal = await TokenValidator(issuer=idp, audience=AUDIENCE).validate_token(token)

        assert principal.subject == "usr_alice"

    async def test_the_claims_asked_for_come_back(self, idp):
        token = _post(
            f"{idp}/dev/token",
            {"subject": "usr_bob", "roles": ["admin"], "permissions": ["boards.write"]},
        )["access_token"]

        principal = await TokenValidator(issuer=idp, audience=AUDIENCE).validate_token(token)

        assert sorted(principal.roles) == ["admin"]
        assert sorted(principal.permissions) == ["boards.write"]

    async def test_a_token_for_another_audience_is_rejected(self, idp):
        token = _post(f"{idp}/dev/token", {})["access_token"]

        with pytest.raises(TokenError):
            await TokenValidator(issuer=idp, audience="somebody-else").validate_token(token)

    async def test_a_tampered_token_is_rejected(self, idp):
        """The signature is checked rather than the payload trusted."""
        token = _post(f"{idp}/dev/token", {"subject": "usr_alice"})["access_token"]
        header, payload, signature = token.split(".")
        forged = f"{header}.{payload}.{signature[:-4]}AAAA"

        with pytest.raises(TokenError):
            await TokenValidator(issuer=idp, audience=AUDIENCE).validate_token(forged)

    async def test_an_expired_token_is_rejected(self, idp):
        token = _post(f"{idp}/dev/token", {"lifetime": -30})["access_token"]

        with pytest.raises(TokenError):
            await TokenValidator(issuer=idp, audience=AUDIENCE).validate_token(token)


class TestExplicitIssuer:
    def test_publishes_what_it_was_told_to(self):
        """For a server behind something that rewrites the host."""
        server = serve(port=0, audience=AUDIENCE, issuer="https://id.example.test")
        threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        ).start()
        try:
            address = f"http://127.0.0.1:{server.server_address[1]}"
            document = _get(f"{address}/.well-known/openid-configuration")
        finally:
            server.shutdown()
            server.server_close()

        assert document["issuer"] == "https://id.example.test"


class TestSigningKey:
    """A supplied key, so tokens survive a restart and match a fixture.

    The default is an ephemeral key, which is what a developer wants until they
    need a token to still work after the server comes back, or to be compared
    against something committed.
    """

    @pytest.fixture(autouse=True)
    def _restore_key(self):
        """Put the process's signing key back after each test.

        ``use_signing_key`` changes it for the whole process, which is right
        for a server and wrong for a test suite: a key installed by one test
        would otherwise sign the tokens of every test after it.
        """
        import oidcutils.dev

        was, was_alg = oidcutils.dev._signing_key, oidcutils.dev._alg
        yield
        oidcutils.dev._signing_key, oidcutils.dev._alg = was, was_alg

    @pytest.fixture
    def ec_jwk(self, tmp_path):
        key = ECKey.generate_key("P-256")
        path = tmp_path / "key.json"
        path.write_text(json.dumps(key.as_dict(private=True)))
        return path

    def test_a_jwk_file_is_loaded(self, ec_jwk):
        assert isinstance(load_signing_key(str(ec_jwk)), ECKey)

    def test_the_key_itself_is_accepted(self, ec_jwk):
        """So the same argument works for a file and for an env var."""
        assert isinstance(load_signing_key(ec_jwk.read_text()), ECKey)

    def test_a_pem_is_accepted(self, tmp_path):
        """A key is as likely to have come from openssl as from here."""
        path = tmp_path / "key.pem"
        path.write_text(ECKey.generate_key("P-256").as_pem(private=True).decode())

        assert isinstance(load_signing_key(str(path)), ECKey)

    def test_an_rsa_pem_is_accepted(self, tmp_path):
        path = tmp_path / "rsa.pem"
        path.write_text(RSAKey.generate_key(2048).as_pem(private=True).decode())

        assert isinstance(load_signing_key(str(path)), RSAKey)

    def test_an_rsa_key_signs_with_rs256(self, tmp_path):
        """The algorithm follows the key, since a mismatch verifies nowhere."""
        path = tmp_path / "rsa.pem"
        path.write_text(RSAKey.generate_key(2048).as_pem(private=True).decode())

        use_signing_key(str(path))

        assert public_jwks()["keys"][0]["alg"] == "RS256"

    def test_nonsense_is_refused(self):
        with pytest.raises(ValueError, match="JWK"):
            load_signing_key("not a key at all")

    def test_the_same_key_gives_the_same_public_jwks(self, ec_jwk):
        """Which is what makes a token reproducible across a restart."""
        use_signing_key(str(ec_jwk))
        first = public_jwks()
        use_signing_key(str(ec_jwk))

        assert public_jwks() == first

    def test_the_env_var_is_read_when_nothing_is_passed(self, ec_jwk, monkeypatch):
        monkeypatch.setenv(KEY_ENV, str(ec_jwk))
        expected = load_signing_key(str(ec_jwk)).as_dict()

        use_signing_key()

        assert public_jwks()["keys"][0]["x"] == expected["x"]

    def test_an_explicit_key_beats_the_env_var(self, ec_jwk, tmp_path, monkeypatch):
        other = tmp_path / "other.json"
        other.write_text(json.dumps(ECKey.generate_key("P-256").as_dict(private=True)))
        monkeypatch.setenv(KEY_ENV, str(other))
        expected = load_signing_key(str(ec_jwk)).as_dict()

        use_signing_key(str(ec_jwk))

        assert public_jwks()["keys"][0]["x"] == expected["x"]

    async def test_a_token_signed_with_a_loaded_key_validates(self, ec_jwk):
        """End to end: the key is loaded, and the validator accepts what it signs."""
        server = serve(port=0, audience=AUDIENCE, signing_key=str(ec_jwk))
        threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        ).start()
        try:
            address = f"http://127.0.0.1:{server.server_address[1]}"
            token = _post(f"{address}/dev/token", {"subject": "usr_alice"})["access_token"]
            principal = await TokenValidator(issuer=address, audience=AUDIENCE).validate_token(
                token
            )
        finally:
            server.shutdown()
            server.server_close()

        assert principal.subject == "usr_alice"
