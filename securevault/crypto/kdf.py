

from __future__ import annotations

from .. import params
from .argon2 import argon2id
from .blake2b import blake2b


def derive_master_key(password: str, salt: bytes,
                      profile: "params.Argon2Profile" = None) -> bytes:
    profile = profile or params.DEFAULT_PROFILE
    return argon2id(
        password.encode("utf-8"),
        salt,
        time_cost=profile.time_cost,
        memory_cost=profile.memory_cost,
        parallelism=profile.parallelism,
        tag_length=params.MASTER_KEY_SIZE,
    )


def derive(secret: bytes, label: bytes, context: bytes = b"",
           length: int = 32) -> bytes:

    if len(secret) > 64:
        raise ValueError("BLAKE2b keys are limited to 64 bytes")
    if len(label) > 16:
        raise ValueError("personalisation strings are limited to 16 bytes")
    return blake2b(context, key=secret, person=label, digest_size=length)


def derive_auth_token(master: bytes) -> bytes:
    return derive(master, params.LABEL_AUTH_TOKEN)


def derive_vault_key(master: bytes) -> bytes:
    return derive(master, params.LABEL_VAULT_KEY,
                  length=params.SYMMETRIC_KEY_SIZE)


def derive_verifier(auth_token: bytes) -> bytes:

    return derive(auth_token, params.LABEL_VERIFIER)


def derive_kek(shared_secret: bytes, sender_id: str, recipient_id: str,
               document_id: bytes) -> bytes:

    context = (sender_id.encode("utf-8") + b"\x00"
               + recipient_id.encode("utf-8") + b"\x00"
               + document_id)
    return derive(shared_secret, params.LABEL_KEK, context,
                  length=params.SYMMETRIC_KEY_SIZE)


def fingerprint(encoded_public_key: bytes) -> bytes:

    return blake2b(encoded_public_key, person=params.LABEL_FINGERPRINT,
                   digest_size=params.FINGERPRINT_SIZE)


def format_fingerprint(encoded_public_key: bytes, groups: int = 8) -> str:

    digits = fingerprint(encoded_public_key).hex()[:groups * 4]
    return " ".join(digits[i:i + 4].upper() for i in range(0, len(digits), 4))
