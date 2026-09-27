import hashlib
import hmac
import unittest

from securevault.crypto.hkdf import (
    hmac_blake2b,
    hkdf_extract,
    hkdf_expand,
    hkdf,
)


HASH_SIZE = 32
PERSON = b"SV-HKDF-v1"


# Reference BLAKE2b implementation used only for testing.
def reference_blake2b(data=b""):
    return hashlib.blake2b(
        data,
        digest_size=HASH_SIZE,
        person=PERSON
    )


# Python's standard HMAC implementation used as a reference.
def reference_hmac(key, data):
    return hmac.new(
        key,
        data,
        digestmod=reference_blake2b
    ).digest()


def reference_extract(ikm, salt=b""):
    if len(salt) == 0:
        salt = b"\x00" * HASH_SIZE

    return reference_hmac(salt, ikm)


def reference_expand(prk, info, length):
    output = b""
    previous_block = b""

    number_of_blocks = length // HASH_SIZE

    if length % HASH_SIZE != 0:
        number_of_blocks += 1

    for counter in range(1, number_of_blocks + 1):
        previous_block = reference_hmac(
            prk,
            previous_block + info + bytes([counter])
        )

        output += previous_block

    return output[:length]


class TestHKDF(unittest.TestCase):

    def test_hmac_with_short_key(self):
        key = b"secret key"
        data = b"message"

        expected = reference_hmac(key, data)
        actual = hmac_blake2b(key, data)

        self.assertEqual(actual, expected)

    def test_hmac_with_long_key(self):
        key = b"K" * 200
        data = b"message"

        expected = reference_hmac(key, data)
        actual = hmac_blake2b(key, data)

        self.assertEqual(actual, expected)

    def test_extract_with_salt(self):
        ikm = b"input key material"
        salt = b"random salt"

        expected = reference_extract(ikm, salt)
        actual = hkdf_extract(ikm, salt)

        self.assertEqual(actual, expected)

    def test_extract_without_salt(self):
        ikm = b"input key material"

        expected = reference_extract(ikm)
        actual = hkdf_extract(ikm)

        self.assertEqual(actual, expected)

    def test_expand_16_bytes(self):
        prk = reference_extract(b"secret", b"salt")
        info = b"SecureVault-AES-128-v1"

        expected = reference_expand(prk, info, 16)
        actual = hkdf_expand(prk, info, 16)

        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), 16)

    def test_expand_32_bytes(self):
        prk = reference_extract(b"secret", b"salt")
        info = b"SecureVault-P256-Private-v1"

        expected = reference_expand(prk, info, 32)
        actual = hkdf_expand(prk, info, 32)

        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), 32)

    def test_expand_multiple_blocks(self):
        prk = reference_extract(b"secret", b"salt")
        info = b"multiple-block-test"

        expected = reference_expand(prk, info, 80)
        actual = hkdf_expand(prk, info, 80)

        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), 80)

    def test_different_info_produces_different_keys(self):
        prk = hkdf_extract(b"secret", b"salt")

        first_key = hkdf_expand(prk, b"AES-KEY", 16)
        second_key = hkdf_expand(prk, b"PRIVATE-KEY", 16)

        self.assertNotEqual(first_key, second_key)

    def test_hkdf_is_deterministic(self):
        first_key = hkdf(b"secret", b"salt", b"AES-KEY", 16)
        second_key = hkdf(b"secret", b"salt", b"AES-KEY", 16)

        self.assertEqual(first_key, second_key)

    def test_complete_hkdf(self):
        ikm = b"original secret"
        salt = b"random salt"
        info = b"SecureVault-AES-128-v1"

        prk = reference_extract(ikm, salt)
        expected = reference_expand(prk, info, 16)

        actual = hkdf(ikm, salt, info, 16)

        self.assertEqual(actual, expected)

    def test_invalid_output_length(self):
        prk = hkdf_extract(b"secret", b"salt")

        with self.assertRaises(ValueError):
            hkdf_expand(prk, b"info", 0)

    def test_invalid_prk_length(self):
        with self.assertRaises(ValueError):
            hkdf_expand(b"short key", b"info", 16)


if __name__ == "__main__":
    unittest.main()