"""The certificate authority -- design decision 7.4.
"""

from __future__ import annotations

import os
import time

from . import formats
from .crypto import ECDSA, P256
from .storage import Storage

CERTIFICATE_LIFETIME_SECONDS = 365 * 24 * 3600


class CertificateError(Exception):
    """Raised when a certificate cannot be trusted."""


class CertificateAuthority:

    def __init__(self, root: str):
        self.storage = Storage(root)
        self._private_key = None
        self._public_key = None
        self._load_or_create()

    def _load_or_create(self) -> None:
        stored = self.storage.get("ca", "signing-key")
        if stored is None:
            private_key, public_key = P256.generate_keypair()
            self.storage.put("ca", "signing-key",
                             P256.encode_scalar(private_key))
            self.storage.put("ca", "public-key", P256.encode_point(public_key))
            self._private_key, self._public_key = private_key, public_key
            return

        self._private_key = P256.decode_scalar(stored)
        self._public_key = P256.decode_point(
            self.storage.get("ca", "public-key"))

    @property
    def public_key(self) -> P256.Point:
        return self._public_key

    def export_trust_anchor(self) -> bytes:

        return P256.encode_point(self._public_key)

    def issue(self, username: str, signing_key: bytes,
              agreement_key: bytes) -> bytes:
        # Validate before signing.  A CA that signs a point which is not on
        # the curve has published an attacker's chosen structure with its own
        # authority attached.
        P256.decode_point(signing_key)
        P256.decode_point(agreement_key)

        if signing_key == agreement_key:
            raise CertificateError("signing and agreement keys must differ")

        now = int(time.time())
        body = formats.encode_certificate_body(
            serial=os.urandom(16),
            username=username,
            signing_key=signing_key,
            agreement_key=agreement_key,
            issued_at=now,
            expires_at=now + CERTIFICATE_LIFETIME_SECONDS,
        )
        signature = ECDSA.sign(self._private_key, body)
        return formats.encode_certificate(body, signature)


def verify_certificate(certificate: bytes, ca_public_key: P256.Point,
                       expected_username: str = None,
                       now: int = None) -> dict:

    try:
        parsed = formats.decode_certificate(certificate)
    except formats.FormatError:
        raise CertificateError("certificate rejected")

    # The signature is checked over the exact bytes on disk, not over a
    # re-encoding of the parsed fields.
    if not ECDSA.verify(ca_public_key, parsed["body"], parsed["signature"]):
        raise CertificateError("certificate rejected")

    now = int(time.time()) if now is None else now
    if not parsed["issued_at"] <= now < parsed["expires_at"]:
        raise CertificateError("certificate rejected")

    # The name binding is the entire point: check it explicitly rather than
    # trusting whoever handed us the file to have looked it up correctly.
    if expected_username is not None and parsed["username"] != expected_username:
        raise CertificateError("certificate rejected")

    try:
        parsed["signing_point"] = P256.decode_point(parsed["signing_key"])
        parsed["agreement_point"] = P256.decode_point(parsed["agreement_key"])
    except P256.InvalidPublicKey:
        raise CertificateError("certificate rejected")

    return parsed
