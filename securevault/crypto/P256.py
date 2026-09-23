
from __future__ import annotations

import os

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
H = 1

FIELD_BYTES = 32
POINT_BYTES = 1 + 2 * FIELD_BYTES      # SEC1 uncompressed: 0x04 || X || Y


class InvalidPublicKey(Exception):
    """Raised when a public key fails validation.

    This is not a formality.  If we accepted an attacker-supplied point that
    is not on P-256, the scalar multiplication in ECDH would happen on some
    other curve -- one the attacker chose, possibly with small subgroups --
    and the shared secret would leak our private key a few bits at a time.
    That is the invalid-curve attack, and the only defence is to check.
    """


class Point:
    """A point on P-256 in affine coordinates.  None coordinates mean O."""

    __slots__ = ("x", "y")

    def __init__(self, x, y):
        self.x = x
        self.y = y

    def __eq__(self, other):
        return isinstance(other, Point) and self.x == other.x and self.y == other.y

    def __hash__(self):
        return hash((self.x, self.y))

    def __repr__(self):
        if self.is_infinity():
            return "Point(infinity)"
        return f"Point(0x{self.x:064x}, 0x{self.y:064x})"

    def is_infinity(self) -> bool:
        return self.x is None


INFINITY = Point(None, None)
G = Point(GX, GY)


def is_on_curve(point: Point) -> bool:
    if point.is_infinity():
        return True
    if not (0 <= point.x < P and 0 <= point.y < P):
        return False
    return (point.y * point.y - (point.x * point.x * point.x
                                 + A * point.x + B)) % P == 0


# ----- Jacobian implementation ------
#
# Affine addition needs a modular inverse every time, which costs about as
# much as 80 multiplications.  Jacobian coordinates (X : Y : Z) represent the
# affine point (X/Z^2, Y/Z^3) and defer all the inversions to a single one at
# the very end.  This is an efficiency choice only -- the results are
# identical, and test_p256.py checks the two agree.

def _jacobian_double(pt):
    x, y, z = pt
    if y == 0 or z == 0:
        return (0, 0, 0)

    delta = (z * z) % P
    gamma = (y * y) % P
    beta = (x * gamma) % P
    alpha = (3 * (x - delta) * (x + delta)) % P
    x3 = (alpha * alpha - 8 * beta) % P
    z3 = ((y + z) * (y + z) - gamma - delta) % P
    y3 = (alpha * (4 * beta - x3) - 8 * gamma * gamma) % P
    return (x3, y3, z3)


def _jacobian_add(p1, p2):
    x1, y1, z1 = p1
    x2, y2, z2 = p2
    if z1 == 0:
        return p2
    if z2 == 0:
        return p1

    z1z1 = (z1 * z1) % P
    z2z2 = (z2 * z2) % P
    u1 = (x1 * z2z2) % P
    u2 = (x2 * z1z1) % P
    s1 = (y1 * z2 * z2z2) % P
    s2 = (y2 * z1 * z1z1) % P

    if u1 == u2:
        if s1 != s2:
            return (0, 0, 0)
        return _jacobian_double(p1)

    h = (u2 - u1) % P
    i = (2 * h) % P
    i = (i * i) % P
    j = (h * i) % P
    r = (2 * (s2 - s1)) % P
    v = (u1 * i) % P
    x3 = (r * r - j - 2 * v) % P
    y3 = (r * (v - x3) - 2 * s1 * j) % P
    z3 = (((z1 + z2) * (z1 + z2) - z1z1 - z2z2) * h) % P
    return (x3, y3, z3)


def _to_jacobian(point: Point):
    if point.is_infinity():
        return (0, 0, 0)
    return (point.x, point.y, 1)


def _from_jacobian(pt) -> Point:
    x, y, z = pt
    if z == 0:
        return INFINITY

    z_inv = pow(z, P - 2, P)
    z_inv2 = (z_inv * z_inv) % P
    return Point((x * z_inv2) % P, (y * z_inv2 * z_inv) % P)


def add(p1: Point, p2: Point) -> Point:
    return _from_jacobian(_jacobian_add(_to_jacobian(p1), _to_jacobian(p2)))


def double(point: Point) -> Point:
    return _from_jacobian(_jacobian_double(_to_jacobian(point)))


def negate(point: Point) -> Point:
    if point.is_infinity():
        return INFINITY
    return Point(point.x, (-point.y) % P)


def scalar_mult(k: int, point: Point) -> Point:

    if k < 0:
        return scalar_mult(-k, negate(point))
    k %= N
    if k == 0 or point.is_infinity():
        return INFINITY

    base = _to_jacobian(point)
    r0 = (0, 0, 0)
    for bit_index in range(k.bit_length() - 1, -1, -1):
        r0 = _jacobian_double(r0)
        r1 = _jacobian_add(r0, base)
        r0 = r1 if (k >> bit_index) & 1 else r0
    return _from_jacobian(r0)


def scalar_mult_base(k: int) -> Point:
    return scalar_mult(k, G)


def double_scalar_mult(u1: int, u2: int, point: Point) -> Point:

    return add(scalar_mult(u1, G), scalar_mult(u2, point))


# ------------------------------------------------------------ serialisation

def encode_point(point: Point) -> bytes:

    if point.is_infinity():
        raise ValueError("the point at infinity is not a valid public key")
    return (b"\x04" + point.x.to_bytes(FIELD_BYTES, "big")
            + point.y.to_bytes(FIELD_BYTES, "big"))


def decode_point(data: bytes) -> Point:
    if len(data) != POINT_BYTES or data[0] != 0x04:
        raise InvalidPublicKey("malformed point encoding")
    point = Point(int.from_bytes(data[1:1 + FIELD_BYTES], "big"),
                  int.from_bytes(data[1 + FIELD_BYTES:], "big"))
    validate_public_key(point)
    return point


def validate_public_key(point: Point) -> None:

    if point.is_infinity():
        raise InvalidPublicKey("public key is the point at infinity")
    if not (0 <= point.x < P and 0 <= point.y < P):
        raise InvalidPublicKey("coordinate out of range")
    if not is_on_curve(point):
        raise InvalidPublicKey("point is not on P-256")


# ------------------------------------------------------------ key generation

def generate_private_key() -> int:

    while True:
        candidate = int.from_bytes(os.urandom(FIELD_BYTES), "big")
        if 1 <= candidate < N:
            return candidate


def public_key_from_private(private_key: int) -> Point:
    if not 1 <= private_key < N:
        raise ValueError("private key out of range")
    return scalar_mult_base(private_key)


def generate_keypair():
    private_key = generate_private_key()
    return private_key, public_key_from_private(private_key)


def encode_scalar(value: int) -> bytes:
    return value.to_bytes(FIELD_BYTES, "big")


def decode_scalar(data: bytes) -> int:
    if len(data) != FIELD_BYTES:
        raise ValueError("scalars are 32 bytes")
    return int.from_bytes(data, "big")
