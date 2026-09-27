import hashlib
import unittest

from securevault.crypto.blake2b import blake2b, blake2b  # noqa: E402


class TestBlake2b(unittest.TestCase):

    def check_against_hashlib(self,data,digest_size=32,key=b"",person=b""):

        expected = hashlib.blake2b(data,digest_size=digest_size,key=key,person=person).digest()

        actual = blake2b(data,digest_size=digest_size,key=key,person=person)

        self.assertEqual(
            actual,
            expected,
            msg=(
                f"\nExpected: {expected.hex()}"f"\nActual:   {actual.hex()}")
        )

    def test_empty_message(self):
        self.check_against_hashlib(b"")

    def test_short_message(self):
        self.check_against_hashlib(b"abc")

    def test_less_than_one_block(self):
        self.check_against_hashlib(b"A" * 127)

    def test_exactly_one_block(self):
        self.check_against_hashlib(b"A" * 128)

    def test_more_than_one_block(self):
        self.check_against_hashlib(b"A" * 129)

    def test_exactly_two_blocks(self):
        self.check_against_hashlib(bytes(range(256)))

    def test_long_message(self):
        self.check_against_hashlib(b"SecureVault" * 100)

    def test_different_digest_sizes(self):
        for digest_size in [1, 16, 32, 48, 64]:
            with self.subTest(digest_size=digest_size):
                self.check_against_hashlib(
                    b"SecureVault",
                    digest_size=digest_size
                )

    def test_keyed_blake2b(self):
        self.check_against_hashlib(
            data=b"Secret message",
            key=b"secret-key"
        )

    def test_personalization(self):
        self.check_against_hashlib(
            data=b"SecureVault",
            person=b"SV-DIGEST-v1"
        )

    def test_key_and_personalization(self):
        self.check_against_hashlib(
            data=b"Secret message" * 20,
            key=b"secret-key",
            person=b"SV-DIGEST-v1"
        )

    def test_personalization_changes_hash(self):
        data = b"same data"

        digest_hash = blake2b(
            data,
            person=b"SV-DIGEST-v1"
        )

        hkdf_hash = blake2b(
            data,
            person=b"SV-HKDF-v1"
        )

        self.assertNotEqual(digest_hash, hkdf_hash)

    def test_invalid_digest_size(self):
        with self.assertRaises(ValueError):
            blake2b(b"abc", digest_size=0)

        with self.assertRaises(ValueError):
            blake2b(b"abc", digest_size=65)

    def test_key_too_long(self):
        with self.assertRaises(ValueError):
            blake2b(b"abc", key=b"K" * 65)

    def test_person_too_long(self):
        with self.assertRaises(ValueError):
            blake2b(b"abc", person=b"P" * 17)

    def test_invalid_data_type(self):
        with self.assertRaises(TypeError):
            blake2b("abc")


if __name__ == "__main__":
    unittest.main()