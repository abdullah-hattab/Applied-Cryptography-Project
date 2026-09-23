"""GCM authentication polynomial, using the bit order in SP 800-38D."""

from aes import require_bytes


def gf_multiply(x, y):
    if not isinstance(x, int) or not isinstance(y, int):
        raise TypeError("field elements must be integers")
    if not 0 <= x < (1 << 128) or not 0 <= y < (1 << 128):
        raise ValueError("field elements must fit in 128 bits")
    result = 0
    value = y
    for bit in range(127, -1, -1):
        if (x >> bit) & 1:
            result ^= value
        low_bit = value & 1
        value >>= 1
        if low_bit:
            value ^= 0xE1000000000000000000000000000000
    return result


def ghash(hash_key, aad, ciphertext):
    require_bytes(hash_key, "hash_key", 16)
    require_bytes(aad, "aad")
    require_bytes(ciphertext, "ciphertext")
    if len(aad) >= (1 << 61) or len(ciphertext) >= (1 << 61):
        raise ValueError("input bit length does not fit in 64 bits")
    h = int.from_bytes(hash_key, "big")
    result = 0
    for data in (aad, ciphertext):
        for offset in range(0, len(data), 16):
            block = data[offset:offset + 16].ljust(16, b"\x00")
            result = gf_multiply(result ^ int.from_bytes(block, "big"), h)
    lengths = (len(aad) * 8).to_bytes(8, "big") + (len(ciphertext) * 8).to_bytes(8, "big")
    result = gf_multiply(result ^ int.from_bytes(lengths, "big"), h)
    return result.to_bytes(16, "big")
