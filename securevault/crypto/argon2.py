

from __future__ import annotations

from .blake2b import blake2b

MASK64 = (1 << 64) - 1
MASK32 = 0xFFFFFFFF
BLOCK_SIZE = 1024          # bytes
WORDS_PER_BLOCK = 128      # 64-bit words
ADDRESSES_PER_BLOCK = 128
SYNC_POINTS = 4            # Argon2 divides each pass into four slices
VERSION = 0x13

TYPE_D = 0
TYPE_I = 1
TYPE_ID = 2


# --------------------------------------------------------------- H' function

def _le32(value: int) -> bytes:
    return value.to_bytes(4, "little")


def _le64(value: int) -> bytes:
    return value.to_bytes(8, "little")


def h_prime(data: bytes, out_len: int) -> bytes:

    if out_len <= 64:
        return blake2b(_le32(out_len) + data, digest_size=out_len)

    r = (out_len + 31) // 32 - 2
    out = bytearray()
    v = blake2b(_le32(out_len) + data, digest_size=64)
    out += v[:32]
    for _ in range(1, r):
        v = blake2b(v, digest_size=64)
        out += v[:32]
    out += blake2b(v, digest_size=out_len - 32 * r)
    return bytes(out)


# ------------------------------------------------- the compression function G

def _rotr64(x: int, n: int) -> int:
    return ((x >> n) | (x << (64 - n))) & MASK64



_ROWS = tuple(tuple(range(16 * r, 16 * r + 16)) for r in range(8))
_COLS = tuple(
    tuple(v for c2 in range(8) for v in (2 * c + 16 * c2, 2 * c + 16 * c2 + 1))
    for c in range(8)
)


def _gb(v: list, a: int, b: int, c: int, d: int) -> None:

    va, vb, vc, vd = v[a], v[b], v[c], v[d]

    va = (va + vb + 2 * (va & MASK32) * (vb & MASK32)) & MASK64
    vd = _rotr64(vd ^ va, 32)
    vc = (vc + vd + 2 * (vc & MASK32) * (vd & MASK32)) & MASK64
    vb = _rotr64(vb ^ vc, 24)
    va = (va + vb + 2 * (va & MASK32) * (vb & MASK32)) & MASK64
    vd = _rotr64(vd ^ va, 16)
    vc = (vc + vd + 2 * (vc & MASK32) * (vd & MASK32)) & MASK64
    vb = _rotr64(vb ^ vc, 63)

    v[a], v[b], v[c], v[d] = va, vb, vc, vd


def _permute(v: list, idx: tuple) -> None:
    _gb(v, idx[0], idx[4], idx[8], idx[12])
    _gb(v, idx[1], idx[5], idx[9], idx[13])
    _gb(v, idx[2], idx[6], idx[10], idx[14])
    _gb(v, idx[3], idx[7], idx[11], idx[15])
    _gb(v, idx[0], idx[5], idx[10], idx[15])
    _gb(v, idx[1], idx[6], idx[11], idx[12])
    _gb(v, idx[2], idx[7], idx[8], idx[13])
    _gb(v, idx[3], idx[4], idx[9], idx[14])


def _fill_block(prev: list, ref: list, out: list, with_xor: bool) -> None:

    r = [prev[i] ^ ref[i] for i in range(WORDS_PER_BLOCK)]
    z = list(r)

    for row in _ROWS:
        _permute(z, row)
    for col in _COLS:
        _permute(z, col)

    if with_xor:
        for i in range(WORDS_PER_BLOCK):
            out[i] ^= z[i] ^ r[i]
    else:
        for i in range(WORDS_PER_BLOCK):
            out[i] = z[i] ^ r[i]


def _block_from_bytes(data: bytes) -> list:
    return [int.from_bytes(data[i * 8:i * 8 + 8], "little")
            for i in range(WORDS_PER_BLOCK)]


def _block_to_bytes(block: list) -> bytes:
    return b"".join(w.to_bytes(8, "little") for w in block)


# ------------------------------------------------------------- block indexing

def _index_alpha(pseudo_rand: int, pass_no: int, slice_no: int, index: int,
                 same_lane: bool, segment_length: int, lane_length: int) -> int:

    if pass_no == 0:
        if slice_no == 0:
            reference_area_size = index - 1
        elif same_lane:
            reference_area_size = slice_no * segment_length + index - 1
        else:
            reference_area_size = (slice_no * segment_length
                                   - (1 if index == 0 else 0))
    else:
        if same_lane:
            reference_area_size = lane_length - segment_length + index - 1
        else:
            reference_area_size = (lane_length - segment_length
                                   - (1 if index == 0 else 0))

    relative = (pseudo_rand * pseudo_rand) >> 32
    relative = reference_area_size - 1 - ((reference_area_size * relative) >> 32)

    if pass_no == 0:
        start_position = 0
    elif slice_no == SYNC_POINTS - 1:
        start_position = 0
    else:
        start_position = (slice_no + 1) * segment_length

    return (start_position + relative) % lane_length


def _next_addresses(address_block: list, input_block: list,
                    zero_block: list) -> None:

    input_block[6] += 1
    _fill_block(zero_block, input_block, address_block, False)
    _fill_block(zero_block, address_block, address_block, False)


# --------------------------------------------------------------- main routine

def argon2(password: bytes, salt: bytes, *, time_cost: int, memory_cost: int,
           parallelism: int, tag_length: int = 32, secret: bytes = b"",
           associated_data: bytes = b"", argon2_type: int = TYPE_ID) -> bytes:

    if parallelism < 1:
        raise ValueError("parallelism must be at least 1")
    if time_cost < 1:
        raise ValueError("time_cost must be at least 1")
    if memory_cost < 8 * parallelism:
        raise ValueError("memory_cost must be at least 8 * parallelism")
    if tag_length < 4:
        raise ValueError("tag_length must be at least 4 bytes")
    if len(salt) < 8:
        raise ValueError("RFC 9106 requires a salt of at least 8 bytes")

    h0 = blake2b(
        _le32(parallelism) + _le32(tag_length) + _le32(memory_cost)
        + _le32(time_cost) + _le32(VERSION) + _le32(argon2_type)
        + _le32(len(password)) + password
        + _le32(len(salt)) + salt
        + _le32(len(secret)) + secret
        + _le32(len(associated_data)) + associated_data,
        digest_size=64,
    )


    blocks = (memory_cost // (SYNC_POINTS * parallelism)) * SYNC_POINTS * parallelism
    lane_length = blocks // parallelism
    segment_length = lane_length // SYNC_POINTS

    memory = [None] * blocks
    for lane in range(parallelism):
        memory[lane * lane_length] = _block_from_bytes(
            h_prime(h0 + _le32(0) + _le32(lane), BLOCK_SIZE))
        memory[lane * lane_length + 1] = _block_from_bytes(
            h_prime(h0 + _le32(1) + _le32(lane), BLOCK_SIZE))

    zero_block = [0] * WORDS_PER_BLOCK

    for pass_no in range(time_cost):
        for slice_no in range(SYNC_POINTS):

            for lane in range(parallelism):

                data_independent = (
                    argon2_type == TYPE_I
                    or (argon2_type == TYPE_ID and pass_no == 0 and slice_no < 2)
                )

                address_block = [0] * WORDS_PER_BLOCK
                input_block = [0] * WORDS_PER_BLOCK
                if data_independent:
                    input_block[0] = pass_no
                    input_block[1] = lane
                    input_block[2] = slice_no
                    input_block[3] = blocks
                    input_block[4] = time_cost
                    input_block[5] = argon2_type

                start = 0
                if pass_no == 0 and slice_no == 0:
                    start = 2
                    if data_independent:
                        _next_addresses(address_block, input_block, zero_block)

                current = (lane * lane_length + slice_no * segment_length + start)
                prev = (current - 1 if current % lane_length
                        else current + lane_length - 1)

                for index in range(start, segment_length):
                    if current % lane_length == 1:
                        prev = current - 1

                    if data_independent:
                        if index % ADDRESSES_PER_BLOCK == 0:
                            _next_addresses(address_block, input_block,
                                            zero_block)
                        pseudo_rand = address_block[index % ADDRESSES_PER_BLOCK]
                    else:
                        pseudo_rand = memory[prev][0]


                    if pass_no == 0 and slice_no == 0:
                        ref_lane = lane
                    else:
                        ref_lane = (pseudo_rand >> 32) % parallelism

                    ref_index = _index_alpha(
                        pseudo_rand & MASK32, pass_no, slice_no, index,
                        ref_lane == lane, segment_length, lane_length)

                    if memory[current] is None:
                        memory[current] = [0] * WORDS_PER_BLOCK

                    _fill_block(memory[prev],
                                memory[ref_lane * lane_length + ref_index],
                                memory[current],
                                with_xor=(pass_no != 0))

                    prev = current
                    current += 1

    final = list(memory[lane_length - 1])
    for lane in range(1, parallelism):
        other = memory[lane * lane_length + lane_length - 1]
        for i in range(WORDS_PER_BLOCK):
            final[i] ^= other[i]

    return h_prime(_block_to_bytes(final), tag_length)


def argon2id(password: bytes, salt: bytes, *, time_cost: int, memory_cost: int,
             parallelism: int, tag_length: int = 32) -> bytes:
    return argon2(password, salt, time_cost=time_cost, memory_cost=memory_cost,
                  parallelism=parallelism, tag_length=tag_length,
                  argon2_type=TYPE_ID)
