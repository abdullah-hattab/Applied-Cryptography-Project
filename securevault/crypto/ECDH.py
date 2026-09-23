
from __future__ import annotations

import P256


def shared_secret(private_key: int, peer_public_key: P256.Point) -> bytes:

    if not 1 <= private_key < P256.N:
        raise ValueError("private key out of range")

    P256.validate_public_key(peer_public_key)

    point = P256.scalar_mult(private_key, peer_public_key)
    if point.is_infinity():

        raise P256.InvalidPublicKey("degenerate shared secret")

    return P256.encode_scalar(point.x)
