import hashlib
import hmac
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ECDH, ECDSA, P256
from P256 import INFINITY, Point

# RFC 6979 Appendix A.2.5 -- the P-256 example key.
RFC6979_PRIVATE = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
RFC6979_PUBLIC_X = 0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6
RFC6979_PUBLIC_Y = 0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299


def _hmac_sha256(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()


# ------------------------------------------------- 1. curve arithmetic

def test_domain_parameters_are_consistent():
    assert P256.P % 4 == 3               # needed if we ever add decompression
    assert P256.A == P256.P - 3          # the a = -3 the fast doubling assumes
    assert P256.is_on_curve(P256.G)
    assert P256.H == 1


def test_group_order():

    assert P256.scalar_mult(P256.N, P256.G).is_infinity()
    assert P256.scalar_mult(P256.N - 1, P256.G) == P256.negate(P256.G)
    assert P256.add(P256.scalar_mult(P256.N - 1, P256.G), P256.G).is_infinity()


def test_infinity_behaves_as_the_identity():
    assert P256.add(P256.G, INFINITY) == P256.G
    assert P256.add(INFINITY, P256.G) == P256.G
    assert P256.add(P256.G, P256.negate(P256.G)).is_infinity()
    assert P256.scalar_mult(0, P256.G).is_infinity()
    assert P256.double(INFINITY).is_infinity()




def _affine_add(p1, p2):
    if p1.is_infinity():
        return p2
    if p2.is_infinity():
        return p1
    if p1.x == p2.x and (p1.y + p2.y) % P256.P == 0:
        return INFINITY
    if p1 == p2:
        lam = ((3 * p1.x * p1.x + P256.A)
               * pow(2 * p1.y, P256.P - 2, P256.P)) % P256.P
    else:
        lam = ((p2.y - p1.y)
               * pow(p2.x - p1.x, P256.P - 2, P256.P)) % P256.P
    x3 = (lam * lam - p1.x - p2.x) % P256.P
    return Point(x3, (lam * (p1.x - x3) - p1.y) % P256.P)


def _affine_scalar_mult(k, point):
    result = INFINITY
    addend = point
    while k:
        if k & 1:
            result = _affine_add(result, addend)
        addend = _affine_add(addend, addend)
        k >>= 1
    return result


def test_jacobian_matches_naive_affine():
    for k in (1, 2, 3, 4, 5, 7, 16, 255, 256, 65537, 2 ** 128 + 1):
        assert P256.scalar_mult(k, P256.G) == _affine_scalar_mult(k, P256.G)

    for _ in range(20):
        k = int.from_bytes(os.urandom(32), "big") % P256.N
        if k == 0:
            continue
        assert P256.scalar_mult(k, P256.G) == _affine_scalar_mult(k, P256.G)


def test_addition_is_associative_and_commutative():
    a = P256.scalar_mult(7, P256.G)
    b = P256.scalar_mult(11, P256.G)
    c = P256.scalar_mult(13, P256.G)
    assert P256.add(a, b) == P256.add(b, a)
    assert P256.add(P256.add(a, b), c) == P256.add(a, P256.add(b, c))
    assert P256.add(a, a) == P256.double(a)
    assert P256.scalar_mult(31, P256.G) == P256.add(P256.add(a, b), c)


def test_all_multiples_stay_on_the_curve():
    for _ in range(30):
        k = 1 + int.from_bytes(os.urandom(32), "big") % (P256.N - 1)
        assert P256.is_on_curve(P256.scalar_mult(k, P256.G))


# ------------------------------------------- 2. scalar multiplication vector

def test_scalar_mult_matches_rfc6979_public_key():
    """An independent published vector: RFC 6979's P-256 private key and the
    public key it derives."""
    public = P256.public_key_from_private(RFC6979_PRIVATE)
    assert public.x == RFC6979_PUBLIC_X
    assert public.y == RFC6979_PUBLIC_Y


# ------------------------------------------------- public key validation

def test_rejects_point_not_on_the_curve():

    encoded = bytearray(P256.encode_point(P256.G))
    encoded[40] ^= 0x01
    with pytest.raises(P256.InvalidPublicKey):
        P256.decode_point(bytes(encoded))


def test_rejects_malformed_encodings():
    for bad in (b"", b"\x04", b"\x02" + b"\x00" * 64, b"\x04" + b"\x00" * 63,
                b"\x04" + b"\x00" * 65):
        with pytest.raises(P256.InvalidPublicKey):
            P256.decode_point(bad)


def test_rejects_infinity_and_out_of_range_coordinates():
    with pytest.raises(P256.InvalidPublicKey):
        P256.validate_public_key(INFINITY)
    with pytest.raises(P256.InvalidPublicKey):
        P256.validate_public_key(Point(P256.P, 1))
    with pytest.raises(P256.InvalidPublicKey):
        P256.validate_public_key(Point(0, 0))


def test_ECDH_refuses_an_invalid_peer_key():
    private, _ = P256.generate_keypair()
    with pytest.raises(P256.InvalidPublicKey):
        ECDH.shared_secret(private, Point(1, 1))


def test_point_encoding_round_trip():
    for _ in range(10):
        _, public = P256.generate_keypair()
        assert P256.decode_point(P256.encode_point(public)) == public
        assert len(P256.encode_point(public)) == P256.POINT_BYTES


# ------------------------------------------------------ 3. RFC 6979 nonces

def test_rfc6979_nonce_construction_matches_published_vectors():
    """Our generate_k() with HMAC-SHA256 must reproduce RFC 6979's own k.

    This is the test that proves the *construction* is right.  Production
    swaps the PRF for keyed BLAKE2b, which changes the output but not a line
    of the surrounding algorithm.
    """
    cases = [
        (b"sample",
         0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60),
        (b"test",
         0xD16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0),
    ]
    for message, expected_k in cases:
        digest = hashlib.sha256(message).digest()
        k = next(ECDSA.generate_k(P256.N, RFC6979_PRIVATE, digest,
                                  _hmac_sha256, 32))
        assert k == expected_k, message


def test_our_blake2b_nonces_are_in_range_and_never_repeat():
    private, _ = P256.generate_keypair()
    seen = set()
    for i in range(50):
        digest = ECDSA.message_digest(f"message {i}".encode())
        k = next(ECDSA.generate_k(P256.N, private, digest))
        assert 1 <= k < P256.N
        seen.add(k)
    assert len(seen) == 50


def test_nonce_is_deterministic_but_key_dependent():
    """Same key and message give the same k -- that is the point.  A different
    key must give a different k, or the PRF is ignoring its key."""
    digest = ECDSA.message_digest(b"a document manifest")
    a = next(ECDSA.generate_k(P256.N, RFC6979_PRIVATE, digest))
    b = next(ECDSA.generate_k(P256.N, RFC6979_PRIVATE, digest))
    c = next(ECDSA.generate_k(P256.N, RFC6979_PRIVATE + 1, digest))
    assert a == b
    assert a != c


# ------------------------------------------- 4. signing and verification

def test_signature_equations_match_rfc6979_vectors():

    cases = [
        (b"sample",
         0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60,
         0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716,
         0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8),
        (b"test",
         0xD16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0,
         0xF1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367,
         0x019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083),
    ]
    public = P256.public_key_from_private(RFC6979_PRIVATE)

    for message, k, expected_r, expected_s in cases:
        digest = hashlib.sha256(message).digest()
        signature = ECDSA.sign_digest(RFC6979_PRIVATE, digest, k=k,
                                      low_s=False)
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        assert r == expected_r, message
        assert s == expected_s, message
        assert ECDSA.verify_digest(public, digest, signature)


def test_sign_and_verify_round_trip():
    private, public = P256.generate_keypair()
    for size in (0, 1, 31, 32, 33, 1000):
        message = os.urandom(size)
        assert ECDSA.verify(public, message, ECDSA.sign(private, message))


def test_signature_is_deterministic():
    private, _ = P256.generate_keypair()
    message = b"the same manifest signed twice"
    assert ECDSA.sign(private, message) == ECDSA.sign(private, message)


def test_signatures_are_low_s():

    private, _ = P256.generate_keypair()
    for i in range(20):
        signature = ECDSA.sign(private, f"message {i}".encode())
        s = int.from_bytes(signature[32:], "big")
        assert s <= P256.N // 2


def test_rejects_a_modified_message():
    private, public = P256.generate_keypair()
    message = b"Layla shares thesis-draft.pdf with Omar"
    signature = ECDSA.sign(private, message)

    for index in range(len(message)):
        forged = bytearray(message)
        forged[index] ^= 0x01
        assert not ECDSA.verify(public, bytes(forged), signature)


def test_rejects_a_modified_signature():
    private, public = P256.generate_keypair()
    message = b"a manifest"
    signature = ECDSA.sign(private, message)

    for index in range(0, len(signature), 7):
        forged = bytearray(signature)
        forged[index] ^= 0x01
        assert not ECDSA.verify(public, message, bytes(forged))


def test_rejects_the_wrong_public_key():

    layla_private, layla_public = P256.generate_keypair()
    _, mallory_public = P256.generate_keypair()
    message = b"a manifest claiming to be from Layla"
    signature = ECDSA.sign(layla_private, message)

    assert ECDSA.verify(layla_public, message, signature)
    assert not ECDSA.verify(mallory_public, message, signature)


def test_rejects_degenerate_and_malformed_signatures():
    _, public = P256.generate_keypair()
    digest = ECDSA.message_digest(b"x")
    zero = (0).to_bytes(32, "big")
    n_bytes = P256.N.to_bytes(32, "big")

    assert not ECDSA.verify_digest(public, digest, zero + zero)
    assert not ECDSA.verify_digest(public, digest, n_bytes + zero)
    assert not ECDSA.verify_digest(public, digest, zero + n_bytes)
    assert not ECDSA.verify_digest(public, digest, b"\x01" * 63)
    assert not ECDSA.verify_digest(public, digest, b"\x01" * 65)
    assert not ECDSA.verify_digest(public, digest, b"")


def test_verify_or_raise():
    private, public = P256.generate_keypair()
    ECDSA.verify_or_raise(public, b"ok", ECDSA.sign(private, b"ok"))
    with pytest.raises(ECDSA.InvalidSignature):
        ECDSA.verify_or_raise(public, b"tampered", ECDSA.sign(private, b"ok"))


# --------------------------------------------------------------------- ECDH

def test_ECDH_agreement():
    layla_private, layla_public = P256.generate_keypair()
    omar_private, omar_public = P256.generate_keypair()

    assert (ECDH.shared_secret(layla_private, omar_public)
            == ECDH.shared_secret(omar_private, layla_public))


def test_ECDH_secrets_differ_per_pair():
    a_private, a_public = P256.generate_keypair()
    b_private, b_public = P256.generate_keypair()
    c_private, c_public = P256.generate_keypair()

    ab = ECDH.shared_secret(a_private, b_public)
    ac = ECDH.shared_secret(a_private, c_public)
    bc = ECDH.shared_secret(b_private, c_public)
    assert len({ab, ac, bc}) == 3
    assert len(ab) == 32


# --------------------------------------------------------------- cross-check

def test_matches_reference_library_if_available():
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils
    except ImportError:
        pytest.skip("python-cryptography not installed; the published "
                    "vectors above are the primary evidence")

    curve = ec.SECP256R1()

    for _ in range(5):
        private, public = P256.generate_keypair()

        # Our scalar multiplication against theirs.
        their_private = ec.derive_private_key(private, curve)
        their_numbers = their_private.public_key().public_numbers()
        assert (their_numbers.x, their_numbers.y) == (public.x, public.y)

        # Our ECDSA signature, verified by their implementation.  We hand
        # them our BLAKE2b digest through the Prehashed interface -- both are
        # 32 bytes, and ECDSA only ever sees the digest.
        message = os.urandom(64)
        digest = ECDSA.message_digest(message)
        signature = ECDSA.sign(private, message)

        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        der = utils.encode_dss_signature(r, s)
        their_private.public_key().verify(
            der, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))

        # Their ECDH against ours.
        peer_private, peer_public = P256.generate_keypair()
        their_peer = ec.derive_private_key(peer_private, curve)
        their_shared = their_peer.exchange(ec.ECDH(), their_private.public_key())
        assert their_shared == ECDH.shared_secret(peer_private, public)
