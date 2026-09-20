"""Local development helpers for minting tokens without an external IdP.

Generates an ephemeral ES256 signing key at import time. The key lives only in
memory and changes on every restart, so nothing has to be created, stored or
cleaned up before a token can be minted.

A restart invalidating every token it issued is usually what a developer wants.
Where it is not, :func:`use_signing_key` loads one instead, and tokens then
survive a restart and can be checked against a committed fixture. See
:func:`load_signing_key` for where a key may come from.
"""

import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path

from joserfc import jwt
from joserfc.jwk import ECKey, KeySet, RSAKey

KID = "dev-key"
ALG = "ES256"
DEFAULT_LIFETIME = 3600

# The env var read when no key is passed. A file is preferred where there is
# one: a key on a command line or in an environment is a key in a shell history
# and in a process listing.
KEY_ENV = "OIDC_DEV_SIGNING_KEY"

_signing_key = ECKey.generate_key("P-256")
_alg = ALG


def _algorithm_for(key: ECKey | RSAKey) -> str:
    """Return the algorithm ``key`` signs with.

    Chosen from the key rather than configured, because a key and an algorithm
    that disagree produce tokens nothing can verify, and the key already says
    which it is.
    """
    if isinstance(key, RSAKey):
        return "RS256"
    curve = key.as_dict().get("crv")
    return {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}.get(str(curve), ALG)


def load_signing_key(source: str) -> ECKey | RSAKey:
    """Return the key ``source`` names, from a file path or the key itself.

    A path is read; anything else is treated as the key's own text, so the same
    argument works for ``--signing-key key.json`` and for an environment
    variable carrying the JSON. Both JWK and PEM are accepted, since a key is
    as likely to have come from ``openssl`` as from this library.

    A JWK set is accepted and its first signing key used, which is what a
    provider's exported keys look like.

    :raises ValueError: if the text is neither a JWK, a JWK set nor a PEM.
    """
    text = Path(source).read_text() if Path(source).is_file() else source
    stripped = text.strip()

    if stripped.startswith("{"):
        parsed = json.loads(stripped)
        if "keys" in parsed:
            return KeySet.import_key_set(parsed).keys[0]
        return ECKey.import_key(parsed) if parsed.get("kty") == "EC" else RSAKey.import_key(parsed)

    if "-----BEGIN" in stripped:
        # A PEM does not say which kind of key it holds in a way worth parsing,
        # so each is tried. joserfc raises its own error rather than a
        # ValueError, which is why this catches broadly and re-raises below.
        for key_type in (ECKey, RSAKey):
            try:
                return key_type.import_key(stripped)
            except Exception:  # noqa: BLE001, S112 - the next type is tried
                continue
        raise ValueError("PEM is neither an EC nor an RSA key")

    raise ValueError("signing key must be a JWK, a JWK set, or a PEM")


def use_signing_key(source: str | None = None) -> ECKey | RSAKey:
    """Sign with the key ``source`` names, and keep signing with it.

    ``None`` reads :data:`KEY_ENV`, and leaves the ephemeral key in place where
    that is unset, so calling this unconditionally at startup is safe.

    Returns whatever is now signing, so a caller can log which key it ended up
    with rather than guess.
    """
    global _signing_key, _alg  # noqa: PLW0603 - one process, one signing key

    resolved = source or os.environ.get(KEY_ENV)
    if resolved:
        _signing_key = load_signing_key(resolved)
        _alg = _algorithm_for(_signing_key)
    return _signing_key


def public_jwks() -> dict:
    """Return the public JWKS containing the dev signing key."""
    # as_dict() omits the private half by default, which is the whole point
    # of what is published here.
    pub = _signing_key.as_dict()
    pub["kid"] = KID
    pub["use"] = "sig"
    pub["alg"] = _alg
    return {"keys": [pub]}


def mint_token(
    *,
    issuer: str,
    audience: str,
    subject: str = "dev-user",
    email: str = "dev@localhost",
    name: str = "Dev User",
    roles: list[str] | None = None,
    permissions: list[str] | None = None,
    lifetime: int = DEFAULT_LIFETIME,
    extra_claims: dict | None = None,
) -> dict:
    """Mint a signed JWT and return a token response dict."""
    now = int(time.time())
    claims = {
        "iss": issuer,
        "aud": audience,
        "sub": subject,
        "email": email,
        "name": name,
        "iat": now,
        "exp": now + lifetime,
        "roles": roles or [],
        "permissions": permissions or [],
    }
    if extra_claims:
        claims.update(extra_claims)

    header = {"alg": _alg, "kid": KID}
    token = jwt.encode(header, claims, _signing_key)

    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": lifetime,
        "refresh_token": secrets.token_urlsafe(32),
    }


def discovery_document(issuer: str) -> dict:
    """Return a minimal OIDC discovery document for local dev."""
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/dev/authorize",
        "token_endpoint": f"{issuer}/dev/token",
        "jwks_uri": f"{issuer}/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": [_alg],
    }


# Authorization codes handed out by the dev provider, each mapping to the
# claims it was issued for. In memory and single use: a restart drops them,
# which is the same promise the signing key makes.
_codes: dict[str, dict] = {}

CODE_LIFETIME = 300


@dataclass(frozen=True)
class DevPersona:
    """Somebody the authorization page offers to sign in as.

    A fixture, not a user record. It carries what an identity server would put
    in a token and nothing an application would decide for itself: no
    memberships, no roles the application owns, because an identity server does
    not know about those.
    """

    key: str
    subject: str
    name: str = ""
    email: str = ""
    # What the picker shows beneath the name, to say what this persona is for.
    purpose: str = ""
    roles: tuple[str, ...] = ()
    permissions: tuple[str, ...] = ()


def issue_code(persona: DevPersona, redirect_uri: str) -> str:
    """Return a fresh authorization code standing for ``persona``.

    The code carries the claims rather than a reference to them, so nothing
    outside this module has to hold state between the authorization page and
    the token exchange.
    """
    code = secrets.token_urlsafe(24)
    _codes[code] = {
        "subject": persona.subject,
        "name": persona.name,
        "email": persona.email,
        "roles": list(persona.roles),
        "permissions": list(persona.permissions),
        "redirect_uri": redirect_uri,
        "expires_at": time.time() + CODE_LIFETIME,
    }
    return code


def redeem_code(code: str) -> dict | None:
    """Return the claims ``code`` stands for, or ``None``.

    Single use. A real provider treats a second presentation as theft, and a
    dev provider that allowed replay would hide a client bug that only appears
    against the real one.
    """
    claims = _codes.pop(code, None)
    if claims is None:
        return None
    if claims["expires_at"] < time.time():
        return None
    return claims
