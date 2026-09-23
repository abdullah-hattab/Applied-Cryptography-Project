import os

import AES as aes


# =============================================================== FIPS 197

def test_fips197_appendix_c1():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plain = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert aes.encrypt_block(key, plain).hex() == \
           "69c4e0d86a7b0430d8cdb78070b4c55a"


def test_fips197_appendix_b():
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    plain = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    assert aes.encrypt_block(key, plain).hex() == \
           "3925841d02dc09fbdc118597196a0b32"


def test_key_expansion_fips197_appendix_a1():
    rk = aes.key_expansion(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"))
    assert len(rk) == 11
    assert all(len(k) == 16 for k in rk)
    assert rk[0].hex() == "2b7e151628aed2a6abf7158809cf4f3c"
    assert rk[10].hex() == "d014f9a8c9ee2589e13f0cc8b6630ca6"



def test_sbox_is_a_permutation():

    assert sorted(aes.SBOX) == list(range(256))


def test_inv_sbox_really_inverts_sbox():
    for i in range(256):
        assert aes.INV_SBOX[aes.SBOX[i]] == i
        assert aes.SBOX[aes.INV_SBOX[i]] == i


def test_sbox_matches_its_mathematical_definition():


    def gf_inverse(x):
        if x == 0:
            return 0
        for candidate in range(1, 256):
            if aes.gf_mul(x, candidate) == 1:
                return candidate
        raise AssertionError("unreachable")

    for value in range(256):
        inv = gf_inverse(value)
        out = 0
        for bit in range(8):
            b = (inv >> bit) & 1
            b ^= (inv >> ((bit + 4) % 8)) & 1
            b ^= (inv >> ((bit + 5) % 8)) & 1
            b ^= (inv >> ((bit + 6) % 8)) & 1
            b ^= (inv >> ((bit + 7) % 8)) & 1
            b ^= (0x63 >> bit) & 1
            out |= b << bit
        assert out == aes.SBOX[value], f"S-box wrong at 0x{value:02x}"


def test_sbox_known_entries():
    assert aes.SBOX[0x00] == 0x63
    assert aes.SBOX[0x53] == 0xED
    assert aes.SBOX[0xFF] == 0x16


# ======================================================== GF(2^8) arithmetic

def test_gf_mul_basics():
    for x in range(256):
        assert aes.gf_mul(x, 1) == x  # 1 is the identity
        assert aes.gf_mul(x, 0) == 0
    assert aes.gf_mul(0x57, 0x83) == 0xc1  # FIPS 197 section 4.2 example
    assert aes.gf_mul(0x57, 0x13) == 0xfe  # FIPS 197 section 4.2.1 example


def test_gf_mul_is_commutative_and_associative():
    for _ in range(200):
        a, b, c = os.urandom(3)
        assert aes.gf_mul(a, b) == aes.gf_mul(b, a)
        assert aes.gf_mul(aes.gf_mul(a, b), c) == aes.gf_mul(a, aes.gf_mul(b, c))


def test_mul_tables_agree_with_gf_mul():
    for constant, table in aes.MUL.items():
        for value in range(256):
            assert table[value] == aes.gf_mul(value, constant)




def test_shift_rows_and_its_inverse():
    state = list(range(16))
    shifted = list(state)
    aes.shift_rows(shifted)
    assert shifted != state
    aes.inv_shift_row(shifted)
    assert shifted == state


def test_shift_rows_moves_the_right_bytes():
    """The state is column-major: byte i is at row i%4, column i//4.
    Row 0 is unchanged; row r rotates left by r."""
    state = list(range(16))
    aes.shift_rows(state)
    assert [state[0], state[4], state[8], state[12]] == [0, 4, 8, 12]
    assert [state[1], state[5], state[9], state[13]] == [5, 9, 13, 1]
    assert [state[2], state[6], state[10], state[14]] == [10, 14, 2, 6]
    assert [state[3], state[7], state[11], state[15]] == [15, 3, 7, 11]


def test_mix_columns_and_its_inverse():
    state = list(os.urandom(16))
    original = list(state)
    aes.mix_columns(state)
    assert state != original
    aes.inv_mix_columns(state)
    assert state == original


def test_mix_columns_fips197_example():
    """the column {d4 bf 5d 30} maps to {04 66 81 e5}."""
    state = [0xd4, 0xbf, 0x5d, 0x30] + [0] * 12
    aes.mix_columns(state)
    assert state[:4] == [0x04, 0x66, 0x81, 0xe5]


def test_sub_byte_and_its_inverse():
    state = list(os.urandom(16))
    original = list(state)
    aes.sub_byte(state)
    aes.inv_sub_byte(state)
    assert state == original


def test_add_round_key_is_its_own_inverse():
    state = list(os.urandom(16))
    original = list(state)
    key = os.urandom(16)
    aes.add_round_key(state, key)
    assert state != original
    aes.add_round_key(state, key)
    assert state == original




def test_decrypt_inverts_encrypt():
    for _ in range(100):
        key, block = os.urandom(16), os.urandom(16)
        cipher = aes.AES_128(key)
        assert cipher.decryption(cipher.encryption(block)) == block


def test_encryption_is_a_permutation_for_a_fixed_key():
    """Different plaintexts must give different ciphertexts.  If two collided,
    the cipher would not be invertible."""
    key = os.urandom(16)
    cipher = aes.AES_128(key)
    seen = {cipher.encryption(i.to_bytes(16, "big")) for i in range(500)}
    assert len(seen) == 500


def test_one_bit_of_plaintext_changes_about_half_the_ciphertext():
    """""  Not a proof of correctness, but a cipher with
    a broken round function usually fails it badly"""
    key = os.urandom(16)
    cipher = aes.AES_128(key)
    total = 0
    trials = 50
    for _ in range(trials):
        plain = bytearray(os.urandom(16))
        first = cipher.encryption(bytes(plain))
        plain[0] ^= 0x01
        second = cipher.encryption(bytes(plain))
        total += sum(bin(x ^ y).count("1") for x, y in zip(first, second))
    average = total / trials
    assert 50 < average < 78, f"average {average} bits of 128 changed"


def test_one_bit_of_key_changes_about_half_the_ciphertext():
    plain = os.urandom(16)
    total = 0
    trials = 50
    for _ in range(trials):
        key = bytearray(os.urandom(16))
        first = aes.encrypt_block(bytes(key), plain)
        key[0] ^= 0x01
        second = aes.encrypt_block(bytes(key), plain)
        total += sum(bin(x ^ y).count("1") for x, y in zip(first, second))
    assert 50 < total / trials < 78




def test_rejects_wrong_key_length():
    for length in (0, 8, 15, 17, 24, 32):
        try:
            aes.AES_128(os.urandom(length))
        except ValueError:
            continue
        raise AssertionError(f"accepted a {length}-byte key")


def test_rejects_wrong_block_length():
    cipher = aes.AES_128(os.urandom(16))
    for length in (0, 8, 15, 17, 32):
        for function in (cipher.encryption, cipher.decryption):
            try:
                function(os.urandom(length))
            except ValueError:
                continue
            raise AssertionError(f"accepted a {length}-byte block")


# ============================================================ cross-check
def test_matches_reference_library_if_available():
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        print("  (skipped: python-cryptography not installed)")
        return

    for _ in range(50):
        key, block = os.urandom(16), os.urandom(16)
        encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
        expected = encryptor.update(block) + encryptor.finalize()
        assert aes.encrypt_block(key, block) == expected


# ======================================================= plain-python runner

if __name__ == "__main__":
    tests = [(name, function) for name, function in sorted(globals().items())
             if name.startswith("test_") and callable(function)]
    failures = 0
    for name, function in tests:
        try:
            function()
            print(f"  PASS  {name}")
        except AssertionError as error:
            failures += 1
            print(f"  FAIL  {name}: {error}")
        except Exception as error:
            failures += 1
            print(f"  ERROR {name}: {type(error).__name__}: {error}")
    print()
    print(f"{len(tests) - failures}/{len(tests)} passed")
    raise SystemExit(1 if failures else 0)
