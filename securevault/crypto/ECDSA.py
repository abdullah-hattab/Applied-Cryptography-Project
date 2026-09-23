
from __future__ import annotations
import P256
import params
from blake2b import blake2b
SIGNATURE_BYTES = 2 * P256.FIELD_BYTES      # r || s, 64 bytes


class InvalidSignature(Exception):
    """Raised when a signature does not verify."""


def message_digest(message: bytes) -> bytes:

    return blake2b(message, digest_size=32, person=params.LABEL_SIG_DIGEST)


def _blake2b_mac(key: bytes, data: bytes) -> bytes:
    return blake2b(data, key=key, digest_size=32, person=params.LABEL_NONCE_PRF)


def _bits2int(data: bytes, qlen: int) -> int:

    value = int.from_bytes(data, "big")
    excess = len(data) * 8 - qlen
    return value >> excess if excess > 0 else value


def generate_k(q: int, private_key: int, digest: bytes, mac=_blake2b_mac,
               mac_length: int = 32):

    qlen = q.bit_length()
    octet_length = (qlen + 7) // 8

    def int2octets(value: int) -> bytes:
        return value.to_bytes(octet_length, "big")

    def bits2octets(data: bytes) -> bytes:
        z1 = _bits2int(data, qlen)
        z2 = z1 - q
        return int2octets(z2 if z2 >= 0 else z1)

    v = b"\x01" * mac_length
    k = b"\x00" * mac_length
    k = mac(k, v + b"\x00" + int2octets(private_key) + bits2octets(digest))
    v = mac(k, v)
    k = mac(k, v + b"\x01" + int2octets(private_key) + bits2octets(digest))
    v = mac(k, v)

    while True:
        t = b""
        while len(t) * 8 < qlen:
            v = mac(k, v)
            t += v
        candidate = _bits2int(t, qlen)
        if 1 <= candidate < q:
            yield candidate
        k = mac(k, v + b"\x00")
        v = mac(k, v)


def sign_digest(private_key: int, digest: bytes, *, k: int = None,
                low_s: bool = True, mac=_blake2b_mac,
                mac_length: int = 32) -> bytes:

    if not 1 <= private_key < P256.N:
        raise ValueError("private key out of range")

    z = _bits2int(digest, P256.N.bit_length())

    nonces = iter([k]) if k is not None else generate_k(
        P256.N, private_key, digest, mac, mac_length)

    for nonce in nonces:
        point = P256.scalar_mult_base(nonce)
        r = point.x % P256.N
        if r == 0:
            continue
        s = (pow(nonce, P256.N - 2, P256.N) * (z + r * private_key)) % P256.N
        if s == 0:
            continue

        if low_s and s > P256.N // 2:
            s = P256.N - s

        return (r.to_bytes(P256.FIELD_BYTES, "big")
                + s.to_bytes(P256.FIELD_BYTES, "big"))

    raise AssertionError("unreachable: the nonce generator never exhausts")


def sign(private_key: int, message: bytes) -> bytes:
    return sign_digest(private_key, message_digest(message))


def verify_digest(public_key: P256.Point, digest: bytes,
                  signature: bytes) -> bool:
 
    if len(signature) != SIGNATURE_BYTES:
        return False

    r = int.from_bytes(signature[:P256.FIELD_BYTES], "big")
    s = int.from_bytes(signature[P256.FIELD_BYTES:], "big")

    if not (1 <= r < P256.N and 1 <= s < P256.N):
        return False

    try:
        P256.validate_public_key(public_key)
    except P256.InvalidPublicKey:
        return False

    z = _bits2int(digest, P256.N.bit_length())
    s_inv = pow(s, P256.N - 2, P256.N)
    u1 = (z * s_inv) % P256.N
    u2 = (r * s_inv) % P256.N

    point = P256.double_scalar_mult(u1, u2, public_key)
    if point.is_infinity():
        return False

    return (point.x % P256.N) == r


def verify(public_key: P256.Point, message: bytes, signature: bytes) -> bool:
    return verify_digest(public_key, message_digest(message), signature)


def verify_or_raise(public_key: P256.Point, message: bytes,
                    signature: bytes) -> None:
    if not verify(public_key, message, signature):
        raise InvalidSignature("signature verification failed")
