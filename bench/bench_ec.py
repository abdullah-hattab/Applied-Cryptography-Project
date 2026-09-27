"""Measure the cost advantage of P-256 over finite-field Diffie-Hellman.



At the 128-bit security level:
  * the elliptic curve needs a 256-bit group (P-256)
  * finite-field DH needs roughly a 3072-bit modulus (NIST SP 800-57)

"""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from securevault.crypto import P256

# MODP group 15 (3072-bit) from RFC 3526 -- the standard finite-field group
# offering about the same 128-bit security level as P-256.
FFDH_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
    "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
    "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
    "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
    "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C"
    "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D"
    "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D"
    "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226"
    "1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC"
    "E0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF", 16)
FFDH_GENERATOR = 2
FFDH_EXPONENT_BITS = 256      # short exponents, as deployments actually use


def measure(label, operation, rounds):
    start = time.perf_counter()
    for _ in range(rounds):
        operation()
    elapsed = (time.perf_counter() - start) / rounds
    print(f"  {label:<42} {elapsed * 1000:>9.2f} ms")
    return elapsed


def main():
    print("One key-agreement operation, same machine, same big-integer backend")
    print()

    scalar = int.from_bytes(os.urandom(32), "big") % P256.N
    exponent = int.from_bytes(os.urandom(FFDH_EXPONENT_BITS // 8), "big")

    ec_time = measure("P-256 scalar multiplication (256-bit)",
                      lambda: P256.scalar_mult_base(scalar), 20)
    ff_time = measure("MODP-3072 modular exponentiation",
                      lambda: pow(FFDH_GENERATOR, exponent, FFDH_PRIME), 20)

    print()
    print(f"  wall-clock ratio: {ff_time / ec_time:.1f}x")
    print()
    print("  This wall-clock figure UNDERSTATES the curve's advantage and we")
    print("  do not quote it as the answer.  Python's pow() is an optimised C")
    print("  modular exponentiation with Montgomery reduction; our curve")
    print("  arithmetic is interpreted Python.  The two are not comparable.")
    print()

    # ---------------------------------------------------------------------
    # The honest comparison: count field multiplications, and measure what a
    # field multiplication costs at each size.  This isolates the mathematics
    # from the quality of each implementation.
    # ---------------------------------------------------------------------
    print("Like-for-like comparison, by counting field multiplications:")
    print()

    small_a = int.from_bytes(os.urandom(32), "big")
    small_b = int.from_bytes(os.urandom(32), "big")
    big_a = int.from_bytes(os.urandom(384), "big")
    big_b = int.from_bytes(os.urandom(384), "big")

    mul_256 = measure("one 256-bit modular multiplication",
                      lambda: (small_a * small_b) % P256.P, 20000)
    mul_3072 = measure("one 3072-bit modular multiplication",
                       lambda: (big_a * big_b) % FFDH_PRIME, 20000)

    # Operation counts for the two algorithms.
    #   P-256, double-and-add-always: one doubling (~8 field mults) and one
    #   addition (~16 field mults) per bit of the scalar.
    #   MODP-3072, square-and-multiply with a 256-bit exponent: one squaring
    #   per bit plus a multiplication for roughly half the bits.
    ec_mults = 256 * (8 + 16)
    ff_mults = 256 + 128

    print()
    print(f"  P-256 scalar multiplication  ~{ec_mults:>6} x 256-bit mults")
    print(f"  MODP-3072 exponentiation     ~{ff_mults:>6} x 3072-bit mults")
    print()
    print(f"  a 3072-bit multiplication costs {mul_3072 / mul_256:.0f}x "
          f"a 256-bit one (measured)")
    print(f"  => finite-field DH costs "
          f"{(ff_mults * mul_3072) / (ec_mults * mul_256):.1f}x "
          f"the curve, at equal security")
    print()
    print("  Our curve figure is pessimistic on purpose: scalar_mult() uses")
    print("  double-and-add-ALWAYS, performing a dummy addition on every")
    print("  zero bit so the operation sequence does not depend on the key.")
    plain = 256 * 8 + 128 * 16
    print(f"  A plain double-and-add would need ~{plain} field")
    print(f"  multiplications instead of {ec_mults}, putting the ratio at "
          f"{(ff_mults * mul_3072) / (plain * mul_256):.1f}x.")
    print("  We report the number our actual code achieves, not the better")
    print("  one we could have had by dropping the side-channel defence.")
    print()
    print("Sizes at the same security level:")
    print(f"  P-256 public key      {P256.POINT_BYTES:>5} bytes")
    print(f"  MODP-3072 public key  {3072 // 8:>5} bytes"
          f"   ({(3072 // 8) / P256.POINT_BYTES:.1f}x larger)")
    print(f"  P-256 signature       {64:>5} bytes")


if __name__ == "__main__":
    main()
