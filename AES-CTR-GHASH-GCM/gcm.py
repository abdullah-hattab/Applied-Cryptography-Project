"""AES-128-GCM with exactly 12-byte nonces and 16-byte tags.

"""

from hmac import compare_digest

from aes import AES128, require_bytes
from ctr import _apply_counter
from ghash import ghash

MAX_DATA_BYTES = (1 << 36) - 32


class AuthenticationError(ValueError):
    pass


def _validate(key, nonce, data, aad):
    require_bytes(key, "key", 16)
    require_bytes(nonce, "nonce", 12)
    require_bytes(data, "data")
    require_bytes(aad, "aad")
    if len(data) > MAX_DATA_BYTES:
        raise ValueError("GCM message is too long")
    if len(aad) >= (1 << 61):
        raise ValueError("AAD is too long")


def _tag(cipher, nonce, ciphertext, aad):
    h = cipher.encrypt_block(bytes(16))
    j0 = nonce + b"\x00\x00\x00\x01"
    mask = cipher.encrypt_block(j0)
    hashed = ghash(h, aad, ciphertext)
    return bytes(a ^ b for a, b in zip(mask, hashed))


def encrypt(key, nonce, plaintext, aad=b""):
    _validate(key, nonce, plaintext, aad)
    cipher = AES128(key)
    ciphertext = _apply_counter(cipher, nonce + b"\x00\x00\x00\x02", plaintext, 32)
    return ciphertext, _tag(cipher, nonce, ciphertext, aad)


def decrypt(key, nonce, ciphertext, tag, aad=b""):
    _validate(key, nonce, ciphertext, aad)
    require_bytes(tag, "tag")
    if len(tag) != 16:
        raise AuthenticationError("authentication failed")
    cipher = AES128(key)
    expected = _tag(cipher, nonce, ciphertext, aad)
    if not compare_digest(expected, tag):
        raise AuthenticationError("authentication failed")
    return _apply_counter(cipher, nonce + b"\x00\x00\x00\x02", ciphertext, 32)
