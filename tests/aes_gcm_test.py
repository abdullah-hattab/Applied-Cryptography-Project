"""Correctness tests for our from-scratch AES-128, CTR, GHASH and GCM.



"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from securevault.crypto import gcm  # noqa: E402
from securevault.crypto.aes import AES128, SBOX, INV_SBOX, key_expansion  # noqa: E402


# ------------------------------------------------------------------ AES core

def test_sbox_is_a_permutation():
    """Our S-box is computed, not copied, so first check it is even a bijection."""
    assert sorted(SBOX) == list(range(256))
    for i in range(256):
        assert INV_SBOX[SBOX[i]] == i


def test_sbox_known_entries():
    """Spot-check against FIPS 197 Figure 7: S(0x00)=0x63, S(0x53)=0xed,
    S(0x01)=0x7c, S(0xff)=0x16."""
    assert SBOX[0x00] == 0x63
    assert SBOX[0x01] == 0x7C
    assert SBOX[0x53] == 0xED
    assert SBOX[0xFF] == 0x16


def test_key_expansion_fips197_appendix_a1():
    """FIPS 197 A.1: the last round key for the cipher key 2b7e...4f3c."""
    round_keys = key_expansion(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"))
    assert round_keys[0].hex() == "2b7e151628aed2a6abf7158809cf4f3c"
    assert round_keys[10].hex() == "d014f9a8c9ee2589e13f0cc8b6630ca6"


def test_encrypt_block_fips197_c1():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plain = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert AES128(key).encrypt_block(plain).hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"


def test_encrypt_block_fips197_appendix_b():
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    plain = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    assert AES128(key).encrypt_block(plain).hex() == "3925841d02dc09fbdc118597196a0b32"


def test_decrypt_inverts_encrypt():
    for _ in range(50):
        key, block = os.urandom(16), os.urandom(16)
        cipher = AES128(key)
        assert cipher.decrypt_block(cipher.encrypt_block(block)) == block


def test_rejects_wrong_key_length():
    for length in (0, 8, 15, 17, 24, 32):
        with pytest.raises(ValueError):
            AES128(os.urandom(length))


# ---------------------------------------------------------------- GF(2^128)

def test_table_multiplication_matches_bitwise_reference():

    for _ in range(100):
        h = os.urandom(16)
        x = int.from_bytes(os.urandom(16), "big")
        hasher = gcm.GHash(h)
        assert hasher._mul_by_h(x) == gcm._gf128_mul(x, int.from_bytes(h, "big"))


# ------------------------------------------------------- GCM published cases

def test_gcm_case_1_empty_message():
    key = bytes.fromhex("00000000000000000000000000000000")
    nonce = bytes.fromhex("000000000000000000000000")
    ct, tag = gcm.encrypt(key, nonce, b"", b"")
    assert ct == b""
    assert tag.hex() == "58e2fccefa7e3061367f1d57a4e7455a"


def test_gcm_case_2_one_block():
    key = bytes.fromhex("00000000000000000000000000000000")
    nonce = bytes.fromhex("000000000000000000000000")
    plain = bytes.fromhex("00000000000000000000000000000000")
    ct, tag = gcm.encrypt(key, nonce, plain, b"")
    assert ct.hex() == "0388dace60b6a392f328c2b971b2fe78"
    assert tag.hex() == "ab6e47d42cec13bdf53a67b21257bddf"


def test_gcm_case_3_multi_block_no_aad():
    key = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
    nonce = bytes.fromhex("cafebabefacedbaddecaf888")
    plain = bytes.fromhex(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")
    ct, tag = gcm.encrypt(key, nonce, plain, b"")
    assert ct.hex() == (
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
        "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985")
    assert tag.hex() == "4d5c2af327cd64a62cf35abd2ba6fab4"


def test_gcm_case_4_with_aad_and_partial_block():
    """This is the shape SecureVault actually uses: associated data present,
    and a plaintext length that is not a multiple of 16."""
    key = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
    nonce = bytes.fromhex("cafebabefacedbaddecaf888")
    plain = bytes.fromhex(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
    aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
    ct, tag = gcm.encrypt(key, nonce, plain, aad)
    assert ct.hex() == (
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
        "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091")
    assert tag.hex() == "5bc94fbc3221a5db94fae95ae7121a47"
    assert gcm.decrypt(key, nonce, ct, tag, aad) == plain


# ------------------------------------------------------------ round trip and
# ------------------------------------------------------------ rejection paths

def test_round_trip_over_many_lengths():
    key, nonce = os.urandom(16), os.urandom(12)
    for length in list(range(0, 40)) + [63, 64, 65, 1000]:
        plain = os.urandom(length)
        aad = os.urandom(length % 23)
        ct, tag = gcm.encrypt(key, nonce, plain, aad)
        assert gcm.decrypt(key, nonce, ct, tag, aad) == plain


def test_every_single_bit_flip_in_the_ciphertext_is_rejected():
    key, nonce = os.urandom(16), os.urandom(12)
    plain = b"the contents of a document nobody else may read"
    aad = b"metadata"
    ct, tag = gcm.encrypt(key, nonce, plain, aad)

    for byte_index in range(len(ct)):
        for bit in range(8):
            forged = bytearray(ct)
            forged[byte_index] ^= 1 << bit
            with pytest.raises(gcm.AuthenticationError):
                gcm.decrypt(key, nonce, bytes(forged), tag, aad)


def test_any_change_to_the_aad_is_rejected():
    """This is the metadata-binding property of Section 6, at the primitive
    level: the AAD is not encrypted but it cannot be altered."""
    key, nonce = os.urandom(16), os.urandom(12)
    plain = b"contents"
    aad = b"name=thesis-draft.pdf;size=48219;owner=layla"
    ct, tag = gcm.encrypt(key, nonce, plain, aad)

    for byte_index in range(len(aad)):
        forged = bytearray(aad)
        forged[byte_index] ^= 0x01
        with pytest.raises(gcm.AuthenticationError):
            gcm.decrypt(key, nonce, ct, tag, bytes(forged))


def test_tag_bit_flips_and_wrong_key_and_wrong_nonce_are_rejected():
    key, nonce = os.urandom(16), os.urandom(12)
    ct, tag = gcm.encrypt(key, nonce, b"contents", b"aad")

    for bit in range(128):
        forged = bytearray(tag)
        forged[bit // 8] ^= 1 << (bit % 8)
        with pytest.raises(gcm.AuthenticationError):
            gcm.decrypt(key, nonce, ct, bytes(forged), b"aad")

    with pytest.raises(gcm.AuthenticationError):
        gcm.decrypt(os.urandom(16), nonce, ct, tag, b"aad")
    with pytest.raises(gcm.AuthenticationError):
        gcm.decrypt(key, os.urandom(12), ct, tag, b"aad")


def test_truncated_tag_is_rejected_rather_than_crashing():
    key, nonce = os.urandom(16), os.urandom(12)
    ct, tag = gcm.encrypt(key, nonce, b"contents")
    with pytest.raises(gcm.AuthenticationError):
        gcm.decrypt(key, nonce, ct, tag[:8])


def test_constant_time_equals():
    assert gcm.constant_time_equals(b"abc", b"abc")
    assert not gcm.constant_time_equals(b"abc", b"abd")
    assert not gcm.constant_time_equals(b"abc", b"ab")


# --------------------------------------------------------------- cross-check

def test_matches_reference_library_if_available():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        pytest.skip("python-cryptography not installed; published vectors "
                    "above are the primary evidence")

    for _ in range(30):
        key, nonce = os.urandom(16), os.urandom(12)
        plain = os.urandom(os.urandom(1)[0])
        aad = os.urandom(os.urandom(1)[0])
        ours_ct, ours_tag = gcm.encrypt(key, nonce, plain, aad)
        theirs = AESGCM(key).encrypt(nonce, plain, aad)
        assert ours_ct + ours_tag == theirs
