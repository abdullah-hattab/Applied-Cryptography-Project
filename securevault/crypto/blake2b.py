from __future__ import annotations


# BLAKE2b processes data using 64-bit words.
# MASK_64 keeps arithmetic operations within 64 bits.
# IV provides the fixed initialization constants.
# SIGMA determines the message-word order in each mixing round.
# SIGMA specifies the message-word order for each of the 12 rounds.
# rotr64 rotates a 64-bit word to the right without losing any bits.

#IV تعطي الخوارزمية حالة بداية ثابتة ومدروسة بدل البدء بأصفار، وتكسر أي تماثل ممكن داخل الحالة ,نخلط القيمة مع البلوك في كل جولة البلوك الاول مع القيمة بطلع النا قيمة اتش بنخلطها مع البلوك الثاني.
#SIGMA تغيّر ترتيب كلمات الرسالة في كل جولة، حتى ما تظل كل كلمة تؤثر في نفس المكان، وينتشر تأثيرها في الحالة كاملة.

# Each 128-byte block is divided into sixteen 64-bit message words.
MASK_64 = (1 << 64) - 1

IV = [
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
]
#SIGMA   → تحدد مين يدخل ومتى
SIGMA = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
]
#بكون داخل ال g هو بقوم بعملية الخلط الفعلية

def rotr64(value, shift):
    value &= MASK_64
    return ((value >> shift) | (value << (64 - shift))) & MASK_64

# Mixes four working-state words with two message words using
# 64-bit modular addition, XOR, and right rotations.
def g(v, a, b, c, d, x, y):
    v[a] = (v[a] + v[b] + x) & MASK_64
    v[d] = rotr64(v[d] ^ v[a], 32)

    v[c] = (v[c] + v[d]) & MASK_64
    v[b] = rotr64(v[b] ^ v[c], 24)

    v[a] = (v[a] + v[b] + y) & MASK_64
    v[d] = rotr64(v[d] ^ v[a], 16)

    v[c] = (v[c] + v[d]) & MASK_64
    v[b] = rotr64(v[b] ^ v[c], 63)

# Compresses one 128-byte message block into the chaining state h.
def compress(h, block, bytes_processed, is_last):
    if len(block) != 128:
        raise ValueError("BLAKE2b block must be exactly 128 bytes")

    # Split the 128-byte block into sixteen 64-bit little-endian words.
    m = []

    for i in range(0, 128, 8):
        eight_bytes = block[i:i + 8]
        word = int.from_bytes(eight_bytes, byteorder="little")
        m.append(word)

    # Create the temporary working state:
    # first 8 words from h, followed by the 8 IV words.
    v = h.copy() + IV.copy()

    # Add the number of processed bytes to the working state.
    v[12] ^= bytes_processed & MASK_64
    v[13] ^= (bytes_processed >> 64) & MASK_64

    # Mark this block as the final block.
    if is_last:
        v[14] ^= MASK_64

    # Perform the 12 BLAKE2b mixing rounds.
    for round_index in range(12):
        s = SIGMA[round_index]

        # Column mixing.
        g(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
        g(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
        g(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
        g(v, 3, 7, 11, 15, m[s[6]], m[s[7]])

        # Diagonal mixing.
        g(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
        g(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
        g(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
        g(v, 3, 4, 9, 14, m[s[14]], m[s[15]])

    # Fold the temporary state back into h.
    for i in range(8):
        h[i] = (h[i] ^ v[i] ^ v[i + 8]) & MASK_64


def initialize_state(digest_size=32, key=b"", person=b""):
    if not 1 <= digest_size <= 64:
        raise ValueError("digest_size must be between 1 and 64 bytes")

    if len(key) > 64:
        raise ValueError("key must not be longer than 64 bytes")

    if len(person) > 16:
        raise ValueError("person must not be longer than 16 bytes")

    # BLAKE2b parameter block is 64 bytes.
    parameter_block = bytearray(64)

    # Output hash length in bytes.
    parameter_block[0] = digest_size

    # Secret-key length. It is zero when no key is used.
    parameter_block[1] = len(key)

    # Sequential hashing mode: fanout = 1 and depth = 1.
    parameter_block[2] = 1
    parameter_block[3] = 1

    # Personalization provides domain separation.
    parameter_block[48:48 + len(person)] = person

    # Initialize h by XORing the IV with the parameter block.
    h = IV.copy()

    for i in range(8):
        start = i * 8
        end = start + 8

        parameter_word = int.from_bytes(parameter_block[start:end],byteorder="little")

        h[i] ^= parameter_word

    return h

def blake2b(data, digest_size=32, key=b"", person=b""):
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes or bytearray")

    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key must be bytes or bytearray")

    if not isinstance(person, (bytes, bytearray)):
        raise TypeError("person must be bytes or bytearray")

    if not isinstance(digest_size, int):
        raise TypeError("digest_size must be an integer")

    data = bytes(data)
    key = bytes(key)
    person = bytes(person)

    # Create the initial chaining state.
    h = initialize_state(digest_size=digest_size,key=key,person=person)

    # If a key is used, BLAKE2b processes it as the first 128-byte block.
    message = b""

    if len(key) > 0:
        key_block = key + b"\x00" * (128 - len(key))
        message += key_block

    message += data

    offset = 0

    # Process all blocks except the final block.
    while len(message) - offset > 128:
        block = message[offset:offset + 128]

        offset += 128

        compress(h=h,block=block,bytes_processed=offset,is_last=False)

    # Get the final block.
    final_block = message[offset:]

    # Count only the bytes that exist before final zero padding.
    bytes_processed = offset + len(final_block)

    # Pad the final block with zeros until it reaches 128 bytes.
    final_block += b"\x00" * (128 - len(final_block))

    compress(h=h,block=final_block,bytes_processed=bytes_processed,is_last=True)

    # Convert the eight 64-bit words of h into bytes.
    result = b""

    for word in h:
        result += word.to_bytes(8, byteorder="little")

    # Return only the requested number of bytes.
    return result[:digest_size]