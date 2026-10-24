"""Fail-closed OIDC access-token validation for management APIs.

Issuer, audience, JWKS endpoint and role mapping are trusted application
configuration. Token headers never select a verification key or URL.
"""

import base64
from dataclasses import dataclass
from functools import lru_cache
import json
import math
import os
import threading
import time
from urllib.parse import urlsplit

import httpx
import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer


ALLOWED_ALGORITHMS = ("ES256", "RS256")
MAX_ACCESS_TOKEN_BYTES = 16 * 1024
MAX_JWKS_BYTES = 256 * 1024
MAX_JWKS_KEYS = 64
JWKS_CACHE_SECONDS = 300
JWKS_UNKNOWN_KID_REFRESH_SECONDS = 5
JWT_CLOCK_SKEW_SECONDS = 30
MAX_ACCESS_TOKEN_LIFETIME_SECONDS = 3600

_bearer = HTTPBearer(auto_error=False)


class OIDCConfigurationError(ValueError):
    """Required trusted OIDC configuration is missing or invalid."""


class JWKSUnavailable(RuntimeError):
    """The configured JWKS cannot be safely fetched or parsed."""


class InvalidAccessToken(ValueError):
    """The supplied access token is not valid for this Controller."""


@dataclass(frozen=True)
class OIDCSettings:
    issuer: str
    audience: str
    jwks_url: str
    role_claim: str
    target_read_role: str
    target_admin_role: str
    enrollment_admin_role: str
    policy_review_role: str | None = None
    audit_read_role: str | None = None

    @classmethod
    def from_env(cls) -> "OIDCSettings":
        names = {
            "issuer": "OIDC_ISSUER",
            "audience": "OIDC_AUDIENCE",
            "jwks_url": "OIDC_JWKS_URL",
            "role_claim": "OIDC_ROLE_CLAIM",
            "target_read_role": "OIDC_TARGET_READ_ROLE",
            "target_admin_role": "OIDC_TARGET_ADMIN_ROLE",
            "enrollment_admin_role": "OIDC_ENROLLMENT_ADMIN_ROLE",
        }
        values = {field: os.environ.get(env, "").strip() for field, env in names.items()}
        if any(not value for value in values.values()):
            raise OIDCConfigurationError("OIDC issuer, audience, JWKS and role configuration are required")
        values["policy_review_role"] = os.environ.get("OIDC_POLICY_REVIEW_ROLE", "").strip() or None
        values["audit_read_role"] = os.environ.get("OIDC_AUDIT_READ_ROLE", "").strip() or None
        settings = cls(**values)
        settings.validate()
        return settings

    def validate(self) -> None:
        for value in (
            self.issuer,
            self.audience,
            self.role_claim,
            self.target_read_role,
            self.target_admin_role,
            self.enrollment_admin_role,
        ):
            if not isinstance(value, str) or not value or len(value) > 512:
                raise OIDCConfigurationError("OIDC configuration contains an invalid value")
        issuer = urlsplit(self.issuer)
        jwks = urlsplit(self.jwks_url)
        if issuer.scheme != "https" or not issuer.netloc or issuer.username or issuer.password or issuer.fragment:
            raise OIDCConfigurationError("OIDC issuer must be an HTTPS URL without user information or fragment")
        if jwks.scheme != "https" or not jwks.netloc or jwks.username or jwks.password or jwks.fragment:
            raise OIDCConfigurationError("OIDC JWKS URL must be HTTPS without user information or fragment")
        if len(self.role_claim) > 128 or any(ch.isspace() for ch in self.role_claim):
            raise OIDCConfigurationError("OIDC role claim name is invalid")
        if self.policy_review_role is not None and (
            not isinstance(self.policy_review_role, str)
            or not self.policy_review_role
            or len(self.policy_review_role) > 128
        ):
            raise OIDCConfigurationError("OIDC policy-review role is invalid")
        if self.audit_read_role is not None and (
            not isinstance(self.audit_read_role, str)
            or not self.audit_read_role
            or len(self.audit_read_role) > 128
        ):
            raise OIDCConfigurationError("OIDC audit-read role is invalid")


@dataclass(frozen=True)
class Principal:
    issuer: str
    subject: str
    roles: frozenset[str]


class JWKSCache:
    """Small, time-bounded JWKS cache with forced refresh for unknown key IDs."""

    def __init__(self, jwks_url: str, fetcher=None, *, ttl: int = JWKS_CACHE_SECONDS):
        self._url = jwks_url
        self._fetcher = fetcher or _fetch_jwks
        self._ttl = ttl
        self._keys: dict[str, dict] = {}
        self._expires_at = 0.0
        self._last_refresh_at = float("-inf")
        self._refresh_retry_after = 0.0
        self._lock = threading.Lock()

    def key_for(self, kid: str, algorithm: str) -> jwt.PyJWK:
        if not kid or len(kid) > 256:
            raise InvalidAccessToken("access token key ID is invalid")
        with self._lock:
            if time.monotonic() >= self._expires_at:
                if time.monotonic() < self._refresh_retry_after:
                    raise JWKSUnavailable("trusted JWKS refresh is temporarily rate limited")
                self._refresh()
            jwk = self._keys.get(kid)
            if jwk is None:
                now = time.monotonic()
                if (
                    now >= self._refresh_retry_after
                    and now - self._last_refresh_at >= JWKS_UNKNOWN_KID_REFRESH_SECONDS
                ):
                    self._refresh()
                jwk = self._keys.get(kid)
            if jwk is None:
                raise InvalidAccessToken("access token signing key is unknown")
            return _validated_jwk(jwk, algorithm)

    def _refresh(self) -> None:
        try:
            document = self._fetcher(self._url)
            keys = document.get("keys") if isinstance(document, dict) else None
            if not isinstance(keys, list) or not keys or len(keys) > MAX_JWKS_KEYS:
                raise ValueError("invalid JWKS key collection")
            indexed: dict[str, dict] = {}
            for key in keys:
                if not isinstance(key, dict):
                    raise ValueError("invalid JWK")
                kid = key.get("kid")
                if not isinstance(kid, str) or not kid or len(kid) > 256 or kid in indexed:
                    raise ValueError("invalid or duplicate JWK key ID")
                indexed[kid] = key
            for key in indexed.values():
                alg = key.get("alg")
                if alg in ALLOWED_ALGORITHMS:
                    _validated_jwk(key, alg)
            self._keys = indexed
            self._last_refresh_at = time.monotonic()
            self._expires_at = self._last_refresh_at + self._ttl
            self._refresh_retry_after = 0.0
        except JWKSUnavailable:
            self._refresh_retry_after = time.monotonic() + JWKS_UNKNOWN_KID_REFRESH_SECONDS
            raise
        except Exception as exc:
            self._refresh_retry_after = time.monotonic() + JWKS_UNKNOWN_KID_REFRESH_SECONDS
            raise JWKSUnavailable("trusted JWKS could not be obtained or validated") from exc


class OIDCAuthenticator:
    def __init__(self, settings: OIDCSettings, *, jwks_fetcher=None):
        settings.validate()
        self.settings = settings
        self._keys = JWKSCache(settings.jwks_url, jwks_fetcher)

    def authenticate(self, token: str) -> Principal:
        if not isinstance(token, str) or not token or len(token.encode("utf-8", errors="ignore")) > MAX_ACCESS_TOKEN_BYTES:
            raise InvalidAccessToken("access token is malformed")
        try:
            segments = token.split(".")
            if len(segments) != 3 or any(not segment for segment in segments):
                raise InvalidAccessToken("access token structure is invalid")
            _strict_json_segment(segments[0])
            _strict_json_segment(segments[1])
            header = jwt.get_unverified_header(token)
            if set(header) - {"alg", "kid", "typ"}:
                raise InvalidAccessToken("access token contains unsupported JOSE headers")
            algorithm = header.get("alg")
            kid = header.get("kid")
            if algorithm not in ALLOWED_ALGORITHMS or not isinstance(kid, str):
                raise InvalidAccessToken("access token algorithm or key ID is invalid")
            if header.get("typ") not in (None, "JWT", "at+jwt"):
                raise InvalidAccessToken("access token type is invalid")
            key = self._keys.key_for(kid, algorithm)
            claims = jwt.decode(
                token,
                key=key.key,
                algorithms=[algorithm],
                issuer=self.settings.issuer,
                audience=self.settings.audience,
                leeway=JWT_CLOCK_SKEW_SECONDS,
                options={"require": ["sub", "iss", "aud", "iat", "exp"]},
            )
            _validate_time_claims(claims)
            subject = claims.get("sub")
            issuer = claims.get("iss")
            roles_value = claims.get(self.settings.role_claim)
            if not isinstance(subject, str) or not subject or len(subject) > 512:
                raise InvalidAccessToken("access token subject is invalid")
            if issuer != self.settings.issuer:
                raise InvalidAccessToken("access token issuer is invalid")
            if isinstance(roles_value, str):
                roles = [roles_value]
            elif isinstance(roles_value, list):
                roles = roles_value
            else:
                raise InvalidAccessToken("access token role claim is missing or malformed")
            if not roles or len(roles) > 128 or any(
                not isinstance(role, str) or not role or len(role) > 128 for role in roles
            ):
                raise InvalidAccessToken("access token role claim is malformed")
            return Principal(issuer=issuer, subject=subject, roles=frozenset(roles))
        except JWKSUnavailable:
            raise
        except InvalidAccessToken:
            raise
        except Exception as exc:
            raise InvalidAccessToken("access token validation failed") from exc


def _validated_jwk(jwk: dict, algorithm: str) -> jwt.PyJWK:
    if algorithm not in ALLOWED_ALGORITHMS:
        raise InvalidAccessToken("access token algorithm is not allowed")
    if jwk.get("use", "sig") != "sig":
        raise InvalidAccessToken("JWK is not a signing key")
    key_ops = jwk.get("key_ops")
    if key_ops is not None and (not isinstance(key_ops, list) or "verify" not in key_ops):
        raise InvalidAccessToken("JWK cannot be used for verification")
    if jwk.get("alg") not in (None, algorithm):
        raise InvalidAccessToken("JWK algorithm does not match token")
    expected_type = "RSA" if algorithm == "RS256" else "EC"
    if jwk.get("kty") != expected_type:
        raise InvalidAccessToken("JWK key type does not match token algorithm")
    if algorithm == "ES256" and jwk.get("crv") != "P-256":
        raise InvalidAccessToken("ES256 requires a P-256 JWK")
    try:
        parsed = jwt.PyJWK.from_dict(jwk, algorithm=algorithm)
        if algorithm == "RS256" and parsed.key.key_size < 2048:
            raise InvalidAccessToken("RS256 requires an RSA key of at least 2048 bits")
        return parsed
    except Exception as exc:
        raise InvalidAccessToken("JWK material is invalid") from exc


def _validate_time_claims(claims: dict) -> None:
    issued = claims.get("iat")
    expires = claims.get("exp")
    not_before = claims.get("nbf", issued)
    for claim in (issued, expires, not_before):
        if (
            isinstance(claim, bool)
            or not isinstance(claim, (int, float))
            or not math.isfinite(claim)
        ):
            raise InvalidAccessToken("access token time claim is invalid")
    if expires <= issued or expires - issued > MAX_ACCESS_TOKEN_LIFETIME_SECONDS:
        raise InvalidAccessToken("access token lifetime is invalid")
    if not_before > expires:
        raise InvalidAccessToken("access token validity interval is invalid")


def _strict_json_segment(segment: str) -> dict:
    try:
        encoded = segment.encode("ascii", errors="strict")
        padded = encoded + b"=" * (-len(encoded) % 4)
        raw = base64.b64decode(padded, altchars=b"-_", validate=True)

        def reject_duplicates(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate JSON member")
                result[key] = value
            return result

        def reject_constant(_value):
            raise ValueError("non-finite JSON number")

        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
        if not isinstance(value, dict):
            raise ValueError("JWT JSON segment must be an object")
        return value
    except Exception as exc:
        raise InvalidAccessToken("access token JSON is malformed or ambiguous") from exc


def _fetch_jwks(url: str) -> dict:
    try:
        with httpx.stream(
            "GET", url, timeout=httpx.Timeout(3.0), follow_redirects=False, trust_env=False
        ) as response:
            response.raise_for_status()
            payload = bytearray()
            for chunk in response.iter_bytes():
                payload.extend(chunk)
                if len(payload) > MAX_JWKS_BYTES:
                    raise JWKSUnavailable("trusted JWKS response exceeds size limit")
        return _parse_jwks(payload)
    except JWKSUnavailable:
        raise
    except Exception as exc:
        raise JWKSUnavailable("trusted JWKS is unavailable") from exc


def _parse_jwks(payload: bytes) -> dict:
    def reject_duplicate_members(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON member")
            result[key] = value
        return result

    def reject_non_finite(_value):
        raise ValueError("non-finite JSON number")

    try:
        document = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=reject_duplicate_members,
            parse_constant=reject_non_finite,
        )
        if not isinstance(document, dict):
            raise ValueError("JWKS is not an object")
        return document
    except Exception as exc:
        raise JWKSUnavailable("trusted JWKS is malformed or ambiguous") from exc


@lru_cache(maxsize=1)
def _configured_authenticator(settings: OIDCSettings) -> OIDCAuthenticator:
    return OIDCAuthenticator(settings)


def get_oidc_settings() -> OIDCSettings:
    try:
        return OIDCSettings.from_env()
    except OIDCConfigurationError as exc:
        raise HTTPException(status_code=503, detail="OIDC authentication is not configured") from exc


def get_current_principal(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    settings: OIDCSettings = Depends(get_oidc_settings),
) -> Principal:
    del request  # Request bodies and caller-supplied identity fields are never consulted.
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer access token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        authenticator = _configured_authenticator(settings)
        return authenticator.authenticate(credentials.credentials)
    except JWKSUnavailable as exc:
        raise HTTPException(status_code=503, detail="OIDC signing keys are unavailable") from exc
    except InvalidAccessToken as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer access token is invalid",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def require_role(role_setting: str):
    def dependency(
        principal: Principal = Depends(get_current_principal),
        settings: OIDCSettings = Depends(get_oidc_settings),
    ) -> Principal:
        required_role = getattr(settings, role_setting)
        if required_role not in principal.roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Required role is missing")
        return principal

    return dependency


require_target_read = require_role("target_read_role")
require_target_admin = require_role("target_admin_role")
require_enrollment_admin = require_role("enrollment_admin_role")


def require_audit_read(
    principal: Principal = Depends(get_current_principal),
    settings: OIDCSettings = Depends(get_oidc_settings),
) -> Principal:
    if not settings.audit_read_role:
        raise HTTPException(status_code=503, detail="Audit-read authorization is not configured")
    if settings.audit_read_role not in principal.roles:
        raise HTTPException(status_code=403, detail="Required role is missing")
    return principal


def require_policy_review(
    principal: Principal = Depends(get_current_principal),
    settings: OIDCSettings = Depends(get_oidc_settings),
) -> Principal:
    if not settings.policy_review_role:
        raise HTTPException(status_code=503, detail="Policy-review authorization is not configured")
    if settings.policy_review_role not in principal.roles:
        raise HTTPException(status_code=403, detail="Required role is missing")
    return principal
