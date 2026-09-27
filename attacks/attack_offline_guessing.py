"""Attack 6: how long would an offline attack on our credential store take?

Section 10.1 sets the standard: a work factor with no measurement behind it is
not a justification.  So every number below is either measured on this machine
or derived from a stated assumption, and the assumptions are printed with the
answer so they can be argued with.

THE ATTACKER'S POSITION
They hold the entire credential store.  For each user that gives them the
salt, the Argon2id parameters and verifier = BLAKE2b(auth_token), where
auth_token = BLAKE2b(Argon2id(password, salt)).  To test one candidate
password they must run the full Argon2id evaluation, then two cheap BLAKE2b
calls.  The Argon2id run dominates completely, so we count that alone.

Salting means this work buys them ONE account.  There is no precomputation
that helps across users and no rainbow table that applies.
"""

import os
import time

from harness import banner, step
from securevault import params
from securevault.crypto.argon2 import argon2id

SECONDS_PER_YEAR = 365.25 * 24 * 3600

# Password spaces, as sizes.
SPACES = [
    ("the 10,000 most common passwords", 10_000),
    ("8 characters, lowercase only (26^8)", 26 ** 8),
    ("8 characters, mixed case + digits (62^8)", 62 ** 8),
    ("4 random words from a 7776-word list", 7776 ** 4),
]

# Attacker hardware assumptions.  Stated, not hidden, so they can be disputed.
GPU_BANDWIDTH_BYTES_PER_SECOND = 1_000e9    # ~1 TB/s, high-end 2024 GPU
GPU_BANDWIDTH_EFFICIENCY = 0.35             # achieved fraction, conservative
GPU_VRAM_BYTES = 24e9
BARE_SHA256_HASHES_PER_SECOND = 20e9        # hashcat-class figure for one GPU


def measure_ours(profile):
    start = time.perf_counter()
    argon2id(b"benchmark", os.urandom(16), time_cost=profile.time_cost,
             memory_cost=profile.memory_cost, parallelism=profile.parallelism,
             tag_length=32)
    return time.perf_counter() - start


def reference_seconds(profile):
    try:
        from argon2.low_level import Type, hash_secret_raw
    except ImportError:
        return None
    start = time.perf_counter()
    hash_secret_raw(b"benchmark", os.urandom(16), time_cost=profile.time_cost,
                    memory_cost=profile.memory_cost,
                    parallelism=profile.parallelism, hash_len=32, type=Type.ID)
    return time.perf_counter() - start


def gpu_guesses_per_second(profile):

    bytes_per_guess = 2 * profile.time_cost * profile.memory_cost * 1024
    by_bandwidth = (GPU_BANDWIDTH_BYTES_PER_SECOND
                    * GPU_BANDWIDTH_EFFICIENCY / bytes_per_guess)
    concurrent = GPU_VRAM_BYTES / (profile.memory_cost * 1024)
    return by_bandwidth, concurrent, bytes_per_guess


def human(seconds):
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    if seconds < 3600:
        return f"{seconds / 60:.1f} minutes"
    if seconds < 86400:
        return f"{seconds / 3600:.1f} hours"
    if seconds < SECONDS_PER_YEAR:
        return f"{seconds / 86400:.1f} days"
    years = seconds / SECONDS_PER_YEAR
    if years > 1e9:
        return f"{years:.2e} years"
    return f"{years:,.0f} years"


def report(profile):
    step(f"Profile: {profile.name}  (m={profile.memory_cost} KiB, "
         f"t={profile.time_cost}, p={profile.parallelism})")

    ours = measure_ours(profile)
    theirs = reference_seconds(profile)
    rate, concurrent, bytes_per_guess = gpu_guesses_per_second(profile)

    print(f"     our Python implementation : {ours:.3f} s per hash (measured)")
    if theirs:
        print(f"     reference C implementation: {theirs * 1000:.1f} ms per "
              f"hash (measured)")
        print(f"     one CPU core gives the attacker "
              f"{1 / theirs:,.0f} guesses/second")
    print(f"     memory moved per guess    : "
          f"{bytes_per_guess / 1e6:.1f} MB")
    print(f"     one GPU, bandwidth-limited: {rate:,.0f} guesses/second")
    print(f"     (VRAM allows {concurrent:,.0f} concurrent instances, so "
          f"capacity is {'not' if concurrent > 64 else 'THE'} the limit)")
    print()
    print(f"     {'password space':<42}{'one GPU':>18}{'1000 GPUs':>18}")
    print(f"     {'-' * 78}")
    for label, size in SPACES:
        # Expected work is half the space for a uniformly chosen password.
        seconds = (size / 2) / rate
        print(f"     {label:<42}{human(seconds):>18}"
              f"{human(seconds / 1000):>18}")


def attack(world):
    banner("Attack 6: offline guessing against the credential store")

    print("\n  Assumptions, stated so they can be argued with:")
    print(f"    GPU memory bandwidth      {GPU_BANDWIDTH_BYTES_PER_SECOND/1e9:.0f} GB/s")
    print(f"    achieved efficiency       {GPU_BANDWIDTH_EFFICIENCY:.0%}")
    print(f"    GPU memory                {GPU_VRAM_BYTES/1e9:.0f} GB")
    print(f"    bare SHA-256 rate         {BARE_SHA256_HASHES_PER_SECOND/1e9:.0f} GH/s")
    print("    expected work is half the space (uniform password)")

    for profile in (params.PRODUCTION, params.DEMO):
        report(profile)

    step("The comparison that shows what the work factor is buying")
    space = 62 ** 8
    bare = (space / 2) / BARE_SHA256_HASHES_PER_SECOND
    rate, _, _ = gpu_guesses_per_second(params.PRODUCTION)
    strong = (space / 2) / rate
    print(f"     8 characters, mixed case + digits, one GPU:")
    print(f"       a single bare SHA-256      {human(bare)}")
    print(f"       Argon2id, production       {human(strong)}")
    print(f"       ratio                      {strong / bare:,.0f}x")

    step("What this does NOT solve, and we say so")
    rate_prod, _, _ = gpu_guesses_per_second(params.PRODUCTION)
    print(f"     A password from the 10,000 most common falls in "
          f"{human((10_000 / 2) / rate_prod)}")
    print("     even at the production work factor.  No work factor fixes a")
    print("     guessable password -- it multiplies the cost of a search, and")
    print("     multiplying a small number leaves a small number.  A")
    print("     dictionary check at sign-up would address this and we have")
    print("     not implemented one; it is in the report under limitations.")
    print()
    print("     The demo profile is visibly inadequate against a real")
    print("     attacker.  It exists only to keep the live demonstration")
    print("     responsive, and the profile name is recorded in every")
    print("     credential record so nobody can mistake which was used.")


if __name__ == "__main__":
    from harness import run
    run(attack)
