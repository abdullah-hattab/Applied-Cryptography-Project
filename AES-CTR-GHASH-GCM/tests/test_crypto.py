import random
import unittest
from unittest.mock import patch

from aes import AES128
from ctr import _apply_counter, ctr_crypt
from gcm import AuthenticationError, decrypt, encrypt
from ghash import gf_multiply, ghash

hx = bytes.fromhex


class KnownAnswers(unittest.TestCase):
    def test_aes_fips197(self):
        cipher = AES128(hx("000102030405060708090a0b0c0d0e0f"))
        self.assertEqual(cipher.encrypt_block(hx("00112233445566778899aabbccddeeff")),
                         hx("69c4e0d86a7b0430d8cdb78070b4c55a"))
        self.assertEqual(bytes(cipher.round_keys[10]), hx("13111d7fe3944a17f307a78b4d2b30c5"))

    def test_ctr_sp800_38a(self):
        key = hx("2b7e151628aed2a6abf7158809cf4f3c")
        counter = hx("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
        plaintext = hx("6bc1bee22e409f96e93d7e117393172a"
                       "ae2d8a571e03ac9c9eb76fac45af8e51"
                       "30c81c46a35ce411e5fbc1191a0a52ef"
                       "f69f2445df4f9b17ad2b417be66c3710")
        expected = hx("874d6191b620e3261bef6864990db6ce"
                      "9806f66b7970fdff8617187bb9fffdff"
                      "5ae4df3edbd5d35e5b4f09020db03eab"
                      "1e031dda2fbe03d1792170a0f3009cee")
        self.assertEqual(ctr_crypt(key, counter, plaintext), expected)
        self.assertEqual(ctr_crypt(key, counter, expected), plaintext)
        self.assertEqual(ctr_crypt(key, counter, plaintext[:23]), expected[:23])

    def test_ghash_known_answer(self):
        h = hx("66e94bd4ef8a2c3b884cfa59ca342b2e")
        c = hx("0388dace60b6a392f328c2b971b2fe78")
        self.assertEqual(ghash(h, b"", c), hx("f38cbb1ad69223dcc3457ae5b6b0f885"))
        self.assertEqual(ghash(h, b"", b""), bytes(16))

    def test_field_product(self):
        x = int("0388dace60b6a392f328c2b971b2fe78", 16)
        h = int("66e94bd4ef8a2c3b884cfa59ca342b2e", 16)
        self.assertEqual(gf_multiply(x, h), int("5e2ec746917062882c85b0685353deb7", 16))
        self.assertEqual(gf_multiply(x, 1 << 127), x)

    def test_gcm_empty(self):
        self.assertEqual(encrypt(bytes(16), bytes(12), b""),
                         (b"", hx("58e2fccefa7e3061367f1d57a4e7455a")))

    def test_gcm_zero_block(self):
        ciphertext, tag = encrypt(bytes(16), bytes(12), bytes(16))
        self.assertEqual(ciphertext, hx("0388dace60b6a392f328c2b971b2fe78"))
        self.assertEqual(tag, hx("ab6e47d42cec13bdf53a67b21257bddf"))
        self.assertEqual(decrypt(bytes(16), bytes(12), ciphertext, tag), bytes(16))

    def test_gcm_aad_partial_block(self):
        key = hx("feffe9928665731c6d6a8f9467308308")
        nonce = hx("cafebabefacedbaddecaf888")
        aad = hx("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        plaintext = hx("d9313225f88406e5a55909c5aff5269a"
                       "86a7a9531534f7da2e4c303d8a318a72"
                       "1c3c0c95956809532fcf0e2449a6b525"
                       "b16aedf5aa0de657ba637b39")
        ciphertext, tag = encrypt(key, nonce, plaintext, aad)
        self.assertEqual(ciphertext, hx("42831ec2217774244b7221b784d0d49c"
                                        "e3aa212f2c02a4e035c17e2329aca12e"
                                        "21d514b25466931c7d8f6a5aac84aa05"
                                        "1ba30b396a0aac973d58e091"))
        self.assertEqual(tag, hx("5bc94fbc3221a5db94fae95ae7121a47"))
        self.assertEqual(decrypt(key, nonce, ciphertext, tag, aad), plaintext)


class RejectionTests(unittest.TestCase):
    def test_every_field_tampering(self):
        key, nonce, aad = bytes(range(16)), bytes(range(12)), b"owner=layla"
        ciphertext, tag = encrypt(key, nonce, b"A private document.", aad)
        fields = [key, nonce, ciphertext, tag, aad]
        # Every byte is exercised, not just the first byte of each field.
        for field_index, field in enumerate(fields):
            for offset in range(len(field)):
                changed = fields.copy()
                changed[field_index] = field[:offset] + bytes([field[offset] ^ 1]) + field[offset + 1:]
                with self.subTest(field=field_index, offset=offset):
                    with self.assertRaises(AuthenticationError):
                        decrypt(*changed)

    def test_failure_never_calls_ctr(self):
        c, tag = encrypt(bytes(16), bytes(12), b"secret")
        with patch("gcm._apply_counter") as counter:
            with self.assertRaises(AuthenticationError):
                decrypt(bytes(16), bytes(12), c, bytes(16))
            counter.assert_not_called()

    def test_bad_lengths_and_types(self):
        for size in (0, 15, 24, 32):
            with self.assertRaises(ValueError):
                AES128(bytes(size))
        for size in (0, 8, 11, 13, 16):
            with self.assertRaises(ValueError):
                encrypt(bytes(16), bytes(size), b"data")
        for size in (0, 15, 17):
            with self.assertRaises(AuthenticationError):
                decrypt(bytes(16), bytes(12), b"", bytes(size))
        with self.assertRaises(TypeError):
            encrypt(bytes(16), bytes(12), "text")
        with self.assertRaises(ValueError):
            AES128(bytes(16)).encrypt_block(b"short")
        with self.assertRaises(ValueError):
            gf_multiply(-1, 0)

    def test_counter_limits(self):
        # A final counter value is usable once; wrapping to zero is refused.
        for bits in (32, 128):
            initial = bytes(16 - bits // 8) + bytes([255]) * (bits // 8)
            self.assertEqual(len(_apply_counter(AES128(bytes(16)), initial, bytes(16), bits)), 16)
            with self.assertRaises(ValueError):
                _apply_counter(AES128(bytes(16)), initial, bytes(17), bits)

    def test_length_limit_before_processing(self):
        with patch("gcm.MAX_DATA_BYTES", 3):
            with self.assertRaises(ValueError):
                encrypt(bytes(16), bytes(12), b"1234")

    def test_truncated_ciphertext(self):
        c, tag = encrypt(bytes(16), bytes(12), b"private document")
        with self.assertRaises(AuthenticationError):
            decrypt(bytes(16), bytes(12), c[:-1], tag)


try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    AESGCM = None


@unittest.skipIf(AESGCM is None, "Install requirements-test.txt for reference comparisons")
class ReferenceTests(unittest.TestCase):
    def test_aes_and_ctr_reference(self):
        rng = random.Random(4320)
        for length in (0, 1, 15, 16, 17, 31, 32, 33, 127, 256):
            key, counter, data = rng.randbytes(16), rng.randbytes(16), rng.randbytes(length)
            reference = Cipher(algorithms.AES(key), modes.CTR(counter)).encryptor()
            self.assertEqual(ctr_crypt(key, counter, data), reference.update(data) + reference.finalize())
            reference = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
            self.assertEqual(AES128(key).encrypt_block(counter), reference.update(counter) + reference.finalize())

    def test_gcm_reference_matrix(self):
        rng = random.Random(1253)
        for length in (0, 1, 15, 16, 17, 31, 32, 33, 64, 255, 1024):
            for aad_length in (0, 1, 15, 16, 17, 33):
                with self.subTest(length=length, aad_length=aad_length):
                    key, nonce = rng.randbytes(16), rng.randbytes(12)
                    data, aad = rng.randbytes(length), rng.randbytes(aad_length)
                    reference = AESGCM(key)
                    expected = reference.encrypt(nonce, data, aad)
                    ciphertext, tag = encrypt(key, nonce, data, aad)
                    self.assertEqual(ciphertext + tag, expected)
                    self.assertEqual(decrypt(key, nonce, expected[:-16], expected[-16:], aad), data)
                    self.assertEqual(reference.decrypt(nonce, ciphertext + tag, aad), data)


if __name__ == "__main__":
    unittest.main()
