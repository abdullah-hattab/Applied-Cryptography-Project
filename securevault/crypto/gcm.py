

from __future__ import annotations

from securevault.crypto.aes import AES128, BLOCK_SIZE

TAG_SIZE = 16
NONCE_SIZE = 12          # 96 bits: the only length GCM treats without hashing
_R = 0xE1 << 120         # the reduction polynomial x^128+x^7+x^2+x+1, reflected


def _gf128_mul(x: int, y: int) -> int:

    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ _R
        else:
            v >>= 1
    return z


class GHash:


    def __init__(self, h: bytes) -> None:
        self.h = int.from_bytes(h, "big")

        # v[i] = H * x^i, i.e. H right-shifted i times with reduction.
        v = [0] * 128
        current = self.h
        for i in range(128):
            v[i] = current
            if current & 1:
                current = (current >> 1) ^ _R
            else:
                current >>= 1

        self._table = []
        for byte_index in range(16):
            entries = [0] * 256
            for value in range(1, 256):
                lowest = value & -value
                bit_in_byte = 7 - (lowest.bit_length() - 1)
                entries[value] = (entries[value ^ lowest]
                                  ^ v[byte_index * 8 + bit_in_byte])
            self._table.append(entries)
        self.y = 0

    def _mul_by_h(self, x: int) -> int:
        table = self._table
        data = x.to_bytes(16, "big")
        result = 0
        for i in range(16):
            result ^= table[i][data[i]]
        return result

    def update(self, data: bytes) -> "GHash":

        if len(data) % BLOCK_SIZE:
            data = data + b"\x00" * (BLOCK_SIZE - len(data) % BLOCK_SIZE)
        y = self.y
        for i in range(0, len(data), BLOCK_SIZE):
            y = self._mul_by_h(y ^ int.from_bytes(data[i:i + BLOCK_SIZE], "big"))
        self.y = y
        return self

    def digest(self) -> bytes:
        return self.y.to_bytes(16, "big")


def ghash(h: bytes, data: bytes) -> bytes:
    return GHash(h).update(data).digest()


def _inc32(block: bytes) -> bytes:
    counter = (int.from_bytes(block[12:], "big") + 1) & 0xFFFFFFFF
    return block[:12] + counter.to_bytes(4, "big")


def ctr_xor(cipher: AES128, initial_counter: bytes, data: bytes) -> bytes:

    out = bytearray()
    counter = initial_counter
    for offset in range(0, len(data), BLOCK_SIZE):
        keystream = cipher.encrypt_block(counter)
        chunk = data[offset:offset + BLOCK_SIZE]
        # XOR a whole block at a time as one big integer.  A byte-by-byte
        # Python loop here made encryption of a 1 MB document take minutes.
        xored = (int.from_bytes(chunk, "big")
                 ^ int.from_bytes(keystream[:len(chunk)], "big"))
        out += xored.to_bytes(len(chunk), "big")
        counter = _inc32(counter)
    return bytes(out)


def _lengths_block(aad: bytes, ciphertext: bytes) -> bytes:
    return ((len(aad) * 8).to_bytes(8, "big")
            + (len(ciphertext) * 8).to_bytes(8, "big"))


def encrypt(key: bytes, nonce: bytes, plaintext: bytes,
            aad: bytes = b"") -> tuple:
    if len(key) != 16:
        raise ValueError("SecureVault uses AES-128: the key must be 16 bytes")
    if len(nonce) != NONCE_SIZE:
        raise ValueError("SecureVault fixes the GCM nonce at 96 bits")

    cipher = AES128(key)
    h = cipher.encrypt_block(b"\x00" * BLOCK_SIZE)      # the hash subkey
    j0 = nonce + b"\x00\x00\x00\x01"

    ciphertext = ctr_xor(cipher, _inc32(j0), plaintext)

    hasher = GHash(h)
    hasher.update(aad)
    hasher.update(ciphertext)
    hasher.update(_lengths_block(aad, ciphertext))
    tag = ctr_xor(cipher, j0, hasher.digest())

    return ciphertext, tag


class AuthenticationError(Exception):
    """Raised when a GCM tag does not verify.

    Deliberately carries no detail about *why*.  Section 7.6 asks what a
    client reports when verification fails: a message that distinguished
    "wrong tag" from "wrong metadata" would hand an attacker an oracle, so
    every failure looks the same from the outside.
    """


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes,
            aad: bytes = b"") -> bytes:

    if len(key) != 16:
        raise ValueError("SecureVault uses AES-128: the key must be 16 bytes")
    if len(nonce) != NONCE_SIZE:
        raise ValueError("SecureVault fixes the GCM nonce at 96 bits")
    if len(tag) != TAG_SIZE:
        raise AuthenticationError("authentication failed")

    cipher = AES128(key)
    h = cipher.encrypt_block(b"\x00" * BLOCK_SIZE)
    j0 = nonce + b"\x00\x00\x00\x01"

    hasher = GHash(h)
    hasher.update(aad)
    hasher.update(ciphertext)
    hasher.update(_lengths_block(aad, ciphertext))
    expected = ctr_xor(cipher, j0, hasher.digest())

    if not constant_time_equals(expected, tag):
        raise AuthenticationError("authentication failed")

    return ctr_xor(cipher, _inc32(j0), ciphertext)


def constant_time_equals(a: bytes, b: bytes) -> bool:

    if len(a) != len(b):
        return False
    difference = 0
    for x, y in zip(a, b):
        difference |= x ^ y
    return difference == 0
