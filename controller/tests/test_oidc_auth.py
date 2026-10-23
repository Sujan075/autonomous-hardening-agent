import base64
import time
import unittest
from unittest.mock import patch

import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from app.auth.oidc import (
    InvalidAccessToken,
    JWKSCache,
    JWKSUnavailable,
    OIDCAuthenticator,
    OIDCConfigurationError,
    OIDCSettings,
    _parse_jwks,
)


ISSUER = "https://identity.example.test/issuer"
AUDIENCE = "hardening-controller"


def settings():
    return OIDCSettings(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks_url="https://identity.example.test/keys",
        role_claim="roles",
        target_read_role="target-reader",
        target_admin_role="target-admin",
        enrollment_admin_role="enrollment-admin",
    )


class OIDCTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.jwk = jwt.algorithms.RSAAlgorithm.to_jwk(cls.private_key.public_key(), as_dict=True)
        cls.jwk.update({"kid": "rsa-1", "alg": "RS256", "use": "sig", "key_ops": ["verify"]})
        cls.document = {"keys": [cls.jwk]}

    def authenticator(self, document=None, fetcher=None):
        source = document or self.document
        return OIDCAuthenticator(
            settings(),
            jwks_fetcher=fetcher or (lambda _url: source),
        )

    def token(self, **overrides):
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "operator-7",
            "iat": now,
            "nbf": now - 1,
            "exp": now + 300,
            "roles": ["target-admin", "enrollment-admin"],
        }
        claims.update(overrides)
        return jwt.encode(claims, self.private_key, algorithm="RS256", headers={"kid": "rsa-1", "typ": "at+jwt"})

    def test_valid_configured_issuer_audience_signature_and_role(self):
        principal = self.authenticator().authenticate(self.token())
        self.assertEqual(principal.issuer, ISSUER)
        self.assertEqual(principal.subject, "operator-7")
        self.assertIn("target-admin", principal.roles)

    def test_wrong_issuer_audience_expiry_future_time_and_missing_claims_rejected(self):
        now = int(time.time())
        cases = [
            {"iss": "https://attacker.example.test"},
            {"aud": "different-service"},
            {"exp": now - 60, "iat": now - 600, "nbf": now - 600},
            {"iat": now + 120, "exp": now + 300, "nbf": now - 1},
            {"nbf": now + 120},
            {"exp": now + 9000},
            {"sub": None},
            {"roles": None},
        ]
        for claims in cases:
            with self.subTest(claims=claims), self.assertRaises(InvalidAccessToken):
                self.authenticator().authenticate(self.token(**claims))

    def test_wrong_role_is_a_valid_identity_without_required_authority(self):
        principal = self.authenticator().authenticate(self.token(roles=["target-reader"]))
        self.assertNotIn("target-admin", principal.roles)

    def test_unknown_kid_refreshes_then_rejects_without_accepting_token_key(self):
        calls = []

        def fetch(url):
            calls.append(url)
            return self.document

        token = jwt.encode(
            {
                "iss": ISSUER, "aud": AUDIENCE, "sub": "operator-7",
                "iat": int(time.time()), "exp": int(time.time()) + 300,
                "roles": ["target-admin"],
            },
            self.private_key,
            algorithm="RS256",
            headers={"kid": "not-registered"},
        )
        with self.assertRaises(InvalidAccessToken):
            self.authenticator(fetcher=fetch).authenticate(token)
        self.assertEqual(len(calls), 1)
        self.assertTrue(all(url == settings().jwks_url for url in calls))

    def test_unknown_kid_refreshes_are_rate_limited(self):
        calls = []
        clock = [100.0]
        cache = JWKSCache(
            settings().jwks_url,
            fetcher=lambda url: calls.append(url) or self.document,
        )
        with patch("app.auth.oidc.time.monotonic", side_effect=lambda: clock[0]):
            for kid in ("unknown-a", "unknown-b"):
                with self.assertRaises(InvalidAccessToken):
                    cache.key_for(kid, "RS256")
            self.assertEqual(len(calls), 1)
            clock[0] += 6
            with self.assertRaises(InvalidAccessToken):
                cache.key_for("unknown-c", "RS256")
            self.assertEqual(len(calls), 2)

    def test_failed_jwks_refreshes_are_rate_limited(self):
        calls = []
        clock = [100.0]

        def unavailable(url):
            calls.append(url)
            raise OSError("unavailable")

        cache = JWKSCache(settings().jwks_url, fetcher=unavailable)
        with patch("app.auth.oidc.time.monotonic", side_effect=lambda: clock[0]):
            for _ in range(2):
                with self.assertRaises(JWKSUnavailable):
                    cache.key_for("rsa-1", "RS256")
            self.assertEqual(len(calls), 1)
            clock[0] += 6
            with self.assertRaises(JWKSUnavailable):
                cache.key_for("rsa-1", "RS256")
            self.assertEqual(len(calls), 2)

    def test_disallowed_algorithms_remote_or_embedded_keys_and_malformed_tokens_rejected(self):
        hs256 = jwt.encode(
            {"sub": "attacker"},
            "not-a-trusted-key",
            algorithm="HS256",
            headers={"kid": "rsa-1"},
        )
        cases = [
            "not-a-jwt",
            jwt.encode({"sub": "x"}, key=None, algorithm="none", headers={"kid": "rsa-1"}),
            hs256,
            jwt.encode(
                {"iss": ISSUER, "aud": AUDIENCE, "sub": "x", "iat": int(time.time()), "exp": int(time.time()) + 60, "roles": ["target-admin"]},
                self.private_key,
                algorithm="RS256",
                headers={"kid": "rsa-1", "jku": "https://attacker.example.test/jwks"},
            ),
            jwt.encode(
                {"iss": ISSUER, "aud": AUDIENCE, "sub": "x", "iat": int(time.time()), "exp": int(time.time()) + 60, "roles": ["target-admin"]},
                self.private_key,
                algorithm="RS256",
                headers={"kid": "rsa-1", "jwk": self.jwk},
            ),
        ]
        for token in cases:
            with self.subTest(token_prefix=token[:20]), self.assertRaises(InvalidAccessToken):
                self.authenticator().authenticate(token)

    def test_duplicate_claims_are_rejected_before_pyjwt_claim_interpretation(self):
        header = base64.urlsafe_b64encode(b'{"alg":"RS256","kid":"rsa-1"}').rstrip(b"=")
        now = int(time.time())
        payload = (
            '{"iss":"' + ISSUER + '","aud":"' + AUDIENCE + '","sub":"one",'
            '"sub":"two","iat":' + str(now) + ',"exp":' + str(now + 120)
            + ',"roles":["target-admin"]}'
        ).encode()
        body = base64.urlsafe_b64encode(payload).rstrip(b"=")
        signing_input = header + b"." + body
        signature = self.private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        token = (signing_input + b"." + base64.urlsafe_b64encode(signature).rstrip(b"=")).decode()
        with self.assertRaises(InvalidAccessToken):
            self.authenticator().authenticate(token)

    def test_es256_with_p256_jwk_is_supported_and_wrong_curve_fails(self):
        private = ec.generate_private_key(ec.SECP256R1())
        jwk = jwt.algorithms.ECAlgorithm.to_jwk(private.public_key(), as_dict=True)
        jwk.update({"kid": "ec-1", "alg": "ES256", "use": "sig"})
        auth = self.authenticator({"keys": [jwk]})
        now = int(time.time())
        token = jwt.encode(
            {"iss": ISSUER, "aud": AUDIENCE, "sub": "operator-ec", "iat": now, "exp": now + 120, "roles": ["target-reader"]},
            private,
            algorithm="ES256",
            headers={"kid": "ec-1"},
        )
        self.assertEqual(auth.authenticate(token).subject, "operator-ec")

        wrong_curve = ec.generate_private_key(ec.SECP384R1())
        wrong_jwk = jwt.algorithms.ECAlgorithm.to_jwk(wrong_curve.public_key(), as_dict=True)
        wrong_jwk.update({"kid": "ec-1", "alg": "ES256", "use": "sig"})
        with self.assertRaises(JWKSUnavailable):
            self.authenticator({"keys": [wrong_jwk]}).authenticate(token)

    def test_jwks_unavailable_and_missing_configuration_fail_closed(self):
        auth = self.authenticator(fetcher=lambda _url: (_ for _ in ()).throw(OSError("offline")))
        with self.assertRaises(JWKSUnavailable):
            auth.authenticate(self.token())
        with self.assertRaises(OIDCConfigurationError):
            OIDCSettings.from_env()

    def test_jwks_duplicate_members_fail_closed(self):
        duplicated = b'{"keys":[{"kid":"first","kid":"second"}]}'
        with self.assertRaises(JWKSUnavailable):
            _parse_jwks(duplicated)

    def test_settings_reject_http_jwks_and_issuer(self):
        with self.assertRaises(OIDCConfigurationError):
            OIDCSettings(**{**settings().__dict__, "jwks_url": "http://identity.example.test/keys"}).validate()
        with self.assertRaises(OIDCConfigurationError):
            OIDCSettings(**{**settings().__dict__, "issuer": "http://identity.example.test"}).validate()


if __name__ == "__main__":
    unittest.main()
