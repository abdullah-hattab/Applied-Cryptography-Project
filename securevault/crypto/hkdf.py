from .blake2b import blake2b


BLAKE2B_BLOCK_SIZE = 128
BLAKE2B_DIGEST_SIZE = 32
HKDF_PERSON = b"SV-HKDF-v1"


def hmac_blake2b(key, data):
    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")

    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")

    # If the key is longer than one BLAKE2b block, hash it first.
    if len(key) > BLAKE2B_BLOCK_SIZE:
        key = blake2b(
            key,
            digest_size=BLAKE2B_DIGEST_SIZE,
            person=HKDF_PERSON
        )

    # Pad the key with zeros until it becomes exactly 128 bytes.
    padded_key = key.ljust(BLAKE2B_BLOCK_SIZE, b"\x00")

    # To Create the inner and outer HMAC keys.
    inner_key = bytes(byte ^ 0x36 for byte in padded_key)
    outer_key = bytes(byte ^ 0x5C for byte in padded_key)

    # First hash: H((key XOR ipad) || data)
    inner_hash = blake2b(
        inner_key + data,
        digest_size=BLAKE2B_DIGEST_SIZE,
        person=HKDF_PERSON
    )

    # Second hash: H((key XOR opad) || inner_hash)
    return blake2b(
        outer_key + inner_hash,
        digest_size=BLAKE2B_DIGEST_SIZE,
        person=HKDF_PERSON
    )

def hkdf_extract(ikm, salt=b""):
    if not isinstance(ikm, bytes):
        raise TypeError("ikm must be bytes")

    if not isinstance(salt, bytes):
        raise TypeError("salt must be bytes")

    # If no salt is provided, HKDF uses a zero-filled salt
    # with the same length as the hash output.
    if len(salt) == 0:
        salt = b"\x00" * BLAKE2B_DIGEST_SIZE

    # Extract produces a fixed 32-byte pseudorandom key.
    return hmac_blake2b(salt, ikm)

def hkdf_expand(prk, info=b"", length=16):
    if not isinstance(prk, bytes):
        raise TypeError("prk must be bytes")

    if not isinstance(info, bytes):
        raise TypeError("info must be bytes")

    if len(prk) != BLAKE2B_DIGEST_SIZE:
        raise ValueError("prk must be exactly 32 bytes")

    if not 1 <= length <= 255 * BLAKE2B_DIGEST_SIZE:
        raise ValueError("invalid output length")

    output = b""
    previous_block = b""

    # Calculate how many 32-byte blocks are needed.
    number_of_blocks = length // BLAKE2B_DIGEST_SIZE

    if length % BLAKE2B_DIGEST_SIZE != 0:
        number_of_blocks += 1

    for counter in range(1, number_of_blocks + 1):
        previous_block = hmac_blake2b(
            prk,
            previous_block + info + bytes([counter])
        )

        output += previous_block

    return output[:length]

def hkdf(ikm, salt=b"", info=b"", length=16):
    # Stage 1: Extract a fixed-size pseudorandom key.
    prk = hkdf_extract(ikm, salt)

    # Stage 2: Expand the PRK into the required key.
    return hkdf_expand(prk, info, length)