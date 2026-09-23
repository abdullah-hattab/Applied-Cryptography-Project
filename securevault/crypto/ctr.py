
from aes import AES128, require_bytes


def _apply_counter(cipher, initial_counter, data, counter_bits):
    require_bytes(initial_counter, "initial_counter", 16)
    require_bytes(data, "data")
    blocks = (len(data) + 15) // 16
    width = counter_bits // 8
    prefix = initial_counter[:-width]
    counter = int.from_bytes(initial_counter[-width:], "big")
    if blocks > (1 << counter_bits) - counter:
        raise ValueError("counter would wrap")
    output = bytearray()
    for offset in range(0, len(data), 16):
        stream = cipher.encrypt_block(prefix + counter.to_bytes(width, "big"))
        block = data[offset:offset + 16]
        output.extend(a ^ b for a, b in zip(block, stream))
        counter += 1
    return bytes(output)


def ctr_crypt(key, initial_counter, data):
    """Encrypt/decrypt using a full 128-bit counter; no padding is added.

    Counter ranges must never overlap under the same key.
    GCM uses its separate 32-bit counter convention internally.
    """
    return _apply_counter(AES128(key), initial_counter, data, 128)
