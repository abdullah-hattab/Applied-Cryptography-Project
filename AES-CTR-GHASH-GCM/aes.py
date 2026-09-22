"""AES-128 block encryption, following FIPS 197. No external libraries."""


def _multiply(a, b):
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = ((a << 1) ^ (0x11B if a & 0x80 else 0)) & 0xFF
        b >>= 1
    return result


def _make_sbox():
    # Invert in GF(2^8), then apply the AES affine transformation.
    table = []
    for value in range(256):
        inverse = 0
        if value:
            inverse, base, exponent = 1, value, 254
            while exponent:
                if exponent & 1:
                    inverse = _multiply(inverse, base)
                base = _multiply(base, base)
                exponent >>= 1
        entry = inverse ^ 0x63
        for shift in range(1, 5):
            entry ^= ((inverse << shift) | (inverse >> (8 - shift))) & 0xFF
        table.append(entry)
    return tuple(table)


SBOX = _make_sbox()


def require_bytes(value, name, length=None):
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    if length is not None and len(value) != length:
        raise ValueError(f"{name} must contain {length} bytes")


class AES128:
    def __init__(self, key):
        require_bytes(key, "key", 16)
        expanded = list(key)
        rcon = 1
        while len(expanded) < 176:
            word = expanded[-4:]
            if len(expanded) % 16 == 0:
                word = [SBOX[x] for x in word[1:] + word[:1]]
                word[0] ^= rcon
                rcon = _multiply(rcon, 2)
            for value in word:
                expanded.append(expanded[-16] ^ value)
        self.round_keys = [expanded[i:i + 16] for i in range(0, 176, 16)]

    def encrypt_block(self, block):
        require_bytes(block, "block", 16)
        # State is column-major: index = 4 * column + row.
        state = [a ^ b for a, b in zip(block, self.round_keys[0])]
        for round_number in range(1, 11):
            state = [SBOX[x] for x in state]
            state = [state[4 * ((column + row) % 4) + row]
                     for column in range(4) for row in range(4)]
            if round_number != 10:
                for offset in range(0, 16, 4):
                    a, b, c, d = state[offset:offset + 4]
                    state[offset:offset + 4] = [
                        _multiply(a, 2) ^ _multiply(b, 3) ^ c ^ d,
                        a ^ _multiply(b, 2) ^ _multiply(c, 3) ^ d,
                        a ^ b ^ _multiply(c, 2) ^ _multiply(d, 3),
                        _multiply(a, 3) ^ b ^ c ^ _multiply(d, 2),
                    ]
            state = [a ^ b for a, b in zip(state, self.round_keys[round_number])]
        return bytes(state)
