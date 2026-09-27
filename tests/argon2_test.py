

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from securevault.crypto.argon2 import (  # noqa: E402
    TYPE_D, TYPE_I, TYPE_ID, argon2, argon2id, h_prime,
)

# RFC 9106 section 5: password 32x0x01, salt 16x0x02, secret 8x0x03,
# associated data 12x0x04, p=4, T=32, m=32, t=3, v=0x13.
RFC_PASSWORD = b"\x01" * 32
RFC_SALT = b"\x02" * 16
RFC_SECRET = b"\x03" * 8
RFC_AD = b"\x04" * 12


def _rfc_tag(argon2_type):
    return argon2(RFC_PASSWORD, RFC_SALT, time_cost=3, memory_cost=32,
                  parallelism=4, tag_length=32, secret=RFC_SECRET,
                  associated_data=RFC_AD, argon2_type=argon2_type).hex()


def test_rfc9106_argon2d():
    assert _rfc_tag(TYPE_D) == (
        "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb")


def test_rfc9106_argon2i():
    assert _rfc_tag(TYPE_I) == (
        "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8")


def test_rfc9106_argon2id():
    """The variant SecureVault uses."""
    assert _rfc_tag(TYPE_ID) == (
        "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")


def test_h_prime_lengths():
    """H' must produce exactly the requested length, including the 1024-byte
    case Argon2 uses to initialise memory, and the boundary at 64."""
    for length in (4, 32, 63, 64, 65, 96, 128, 1024):
        assert len(h_prime(b"input", length)) == length


def test_h_prime_length_is_bound_into_the_output():
    """Different requested lengths must not be prefixes of one another,
    otherwise a 16-byte tag would be the first half of a 32-byte one."""
    assert not h_prime(b"x", 32).startswith(h_prime(b"x", 16))


# ------------------------------------------------------- behavioural checks

def test_salt_changes_the_tag():
    """Requirement 5.1: two users with the same password must not look
    identical in the stored data."""
    a = argon2id(b"same password", b"saltsaltsaltsalt",
                 time_cost=1, memory_cost=32, parallelism=1)
    b = argon2id(b"same password", b"different salttt",
                 time_cost=1, memory_cost=32, parallelism=1)
    assert a != b


def test_every_parameter_changes_the_tag():
    """A tag computed under weak settings must never collide with one
    computed under strong settings -- this is why the parameters go into H0."""
    base = dict(time_cost=1, memory_cost=32, parallelism=1, tag_length=32)
    reference = argon2id(b"pw", b"saltsalt", **base)

    assert argon2id(b"pw", b"saltsalt", **{**base, "time_cost": 2}) != reference
    assert argon2id(b"pw", b"saltsalt", **{**base, "memory_cost": 64}) != reference
    assert argon2id(b"pw", b"saltsalt", **{**base, "parallelism": 2}) != reference
    assert argon2(b"pw", b"saltsalt", **base, argon2_type=TYPE_D) != reference


def test_rejects_invalid_parameters():
    for kwargs in ({"time_cost": 0}, {"parallelism": 0}, {"memory_cost": 4},
                   {"tag_length": 2}):
        params = dict(time_cost=1, memory_cost=32, parallelism=1,
                      tag_length=32)
        params.update(kwargs)
        with pytest.raises(ValueError):
            argon2id(b"pw", b"saltsalt", **params)


def test_rejects_short_salt():
    with pytest.raises(ValueError):
        argon2id(b"pw", b"short", time_cost=1, memory_cost=32, parallelism=1)


# --------------------------------------------------------------- cross-check

def test_matches_reference_implementation_if_available():
    try:
        from argon2.low_level import Type, hash_secret_raw
    except ImportError:
        pytest.skip("argon2-cffi not installed; the RFC vectors above are the "
                    "primary evidence")

    cases = [
        (b"password", b"saltsaltsaltsalt", 1, 32, 1, 32),
        (b"", b"12345678", 2, 64, 2, 16),
        (b"a much longer passphrase than usual", b"NaClNaClNaClNaCl", 3, 128, 4, 64),
        (os.urandom(40), os.urandom(24), 1, 256, 3, 32),
    ]
    for password, salt, t, m, p, length in cases:
        ours = argon2id(password, salt, time_cost=t, memory_cost=m,
                        parallelism=p, tag_length=length)
        theirs = hash_secret_raw(password, salt, time_cost=t, memory_cost=m,
                                 parallelism=p, hash_len=length, type=Type.ID)
        assert ours == theirs, f"mismatch for m={m} t={t} p={p}"
