"""Measure the Argon2id work factor on THIS machine.



"""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from securevault import params
from securevault.crypto.argon2 import argon2id


def time_once(profile):
    salt = os.urandom(params.SALT_SIZE)
    start = time.perf_counter()
    argon2id(b"benchmark password", salt,
             time_cost=profile.time_cost,
             memory_cost=profile.memory_cost,
             parallelism=profile.parallelism,
             tag_length=params.MASTER_KEY_SIZE)
    return time.perf_counter() - start


def reference_time(profile):
    """Same parameters, compiled implementation -- the attacker's speed."""
    try:
        from argon2.low_level import Type, hash_secret_raw
    except ImportError:
        return None
    salt = os.urandom(params.SALT_SIZE)
    start = time.perf_counter()
    hash_secret_raw(b"benchmark password", salt,
                    time_cost=profile.time_cost,
                    memory_cost=profile.memory_cost,
                    parallelism=profile.parallelism,
                    hash_len=params.MASTER_KEY_SIZE, type=Type.ID)
    return time.perf_counter() - start


def main():
    print(f"{'profile':<12} {'m (KiB)':>9} {'t':>3} {'p':>3} "
          f"{'ours':>10} {'reference C':>13} {'ratio':>8}")
    for profile in (params.DEMO, params.PRODUCTION):
        ours = time_once(profile)
        theirs = reference_time(profile)
        ratio = f"{ours / theirs:.0f}x" if theirs else "n/a"
        theirs_s = f"{theirs * 1000:.1f} ms" if theirs else "not installed"
        print(f"{profile.name:<12} {profile.memory_cost:>9} "
              f"{profile.time_cost:>3} {profile.parallelism:>3} "
              f"{ours:>9.2f}s {theirs_s:>13} {ratio:>8}")

    print()
    print("Offline guessing rate an attacker achieves with the compiled")
    print("implementation, per CPU core, at each profile:")
    for profile in (params.DEMO, params.PRODUCTION):
        theirs = reference_time(profile)
        if theirs:
            print(f"  {profile.name:<12} {1 / theirs:>10.0f} guesses/second/core")


if __name__ == "__main__":
    main()
