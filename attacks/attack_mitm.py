"""Attack 1: a man-in-the-middle substituting public key material.

This is the attack Section 7.4 calls the hardest problem in the project, and
it is the one that would break everything else if it worked.  The server does
not need to break AES or ECDSA -- it only needs Layla to encrypt to the wrong
public key.
"""

from harness import banner, result, run, step
from securevault import params
from securevault.ca import CertificateAuthority
from securevault.client import Client, ClientError
from securevault.crypto import P256


def attack(world):
    banner("Attack 1: man-in-the-middle public key substitution")

    print("\n  The malicious server wants to read what Layla sends Omar.")
    print("  It does not attack the cryptography.  It attacks the KEY LOOKUP.")

    # The attacker generates a key pair of their own.
    attacker_signing, attacker_signing_public = P256.generate_keypair()
    attacker_agreement, attacker_agreement_public = P256.generate_keypair()

    # ---------------------------------------------------------------- 1a
    step("1a: serve a raw substituted key with no certificate at all")
    genuine = world.server.raw_object("certificates", "omar")
    world.server.storage.put("certificates", "omar",
                             P256.encode_point(attacker_agreement_public))
    try:
        world.layla._certificate_cache.clear()
        world.layla.certificate_for("omar")
        result(True, "Layla accepted an unsigned key")
    except ClientError as error:
        result(False, f"Layla refused: {error.detail}")
        print("     There is no path in the client that parses a public key")
        print("     without a CA signature over it.")

    # ---------------------------------------------------------------- 1b
    step("1b: sign the substituted key with the attacker's OWN certificate "
         "authority")
    rogue = CertificateAuthority(world.root + "/rogue-ca")
    forged = rogue.issue("omar", P256.encode_point(attacker_signing_public),
                         P256.encode_point(attacker_agreement_public))
    world.server.storage.put("certificates", "omar", forged)
    print("     The certificate is perfectly well-formed, names 'omar',")
    print("     is in date, and carries a valid signature -- under the")
    print("     WRONG authority's key.")
    try:
        world.layla._certificate_cache.clear()
        world.layla.certificate_for("omar")
        result(True, "Layla accepted a certificate from a rogue CA")
    except ClientError as error:
        result(False, f"Layla refused: {error.detail}")
        print("     The client verifies against the ONE public key that")
        print("     reached it out of band.  A signature from any other key")
        print("     is just noise.")

    # ---------------------------------------------------------------- 1c
    step("1c: serve a GENUINE certificate -- the wrong person's")
    laylas_own = world.server.raw_object("certificates", "layla")
    world.server.storage.put("certificates", "omar", laylas_own)
    print("     This certificate really was issued by the real CA.  The")
    print("     signature verifies.  It simply belongs to Layla, not Omar.")
    try:
        world.layla._certificate_cache.clear()
        world.layla.certificate_for("omar")
        result(True, "Layla accepted the wrong person's certificate")
    except ClientError as error:
        result(False, f"Layla refused: {error.detail}")
        print("     The username is INSIDE the signed region, and the client")
        print("     checks it against the name it asked for.  A valid")
        print("     signature over the wrong name is not an answer.")

    # ---------------------------------------------------------------- 1d
    step("1d: give up on the keys -- attack the NAME instead")
    world.server.storage.put("certificates", "omar", genuine)
    print("     The cryptography holds, so the attacker stops attacking it.")
    print("     Instead they register an account whose name LOOKS like")
    print("     Omar's, and wait for Layla to pick the wrong one.")
    print()
    print("     We found this by attacking our own system, and it worked at")
    print("     first: our original username rule accepted any Python")
    print("     identifier, and Python identifiers may contain Unicode.")

    homograph = "om\u0430r"        # CYRILLIC SMALL LETTER A
    print()
    print(f"     candidate name : {homograph}")
    print(f"     equal to 'omar': {homograph == 'omar'}")
    print(f"     code points    : {[hex(ord(c)) for c in homograph]}")
    print("     On screen it is indistinguishable from 'omar'.")

    impostor = Client(world.server, world.ca_public, world.ca)
    try:
        impostor.register(homograph, "impostor-a-long-password", params.DEMO)
        result(True, "a homograph account was registered")
    except ClientError as error:
        result(False, f"registration refused: {error.detail}")
        print("     Fixed: usernames are now restricted to lowercase ASCII")
        print("     letters, digits, underscore and hyphen.  See the note in")
        print("     params.py, which records the attack that motivated it.")

    print()
    print("     WHAT THIS DOES NOT FIX, stated honestly: the ASCII")
    print("     look-alikes remain.  'rnark' against 'mark', 'l' against '1'.")
    print("     Our CA signs whatever name is requested, first come first")
    print("     served, because it has no way to check who is asking.  The")
    print("     real fix is identity verification at registration, which is")
    print("     what a CA is for and which we have not implemented.")
    print("     What a careful user can do instead is compare fingerprints:")
    print()
    print(f"       omar : {world.layla.fingerprint_of('omar')}")
    print(f"       layla: {world.layla.fingerprint_of('layla')}")


if __name__ == "__main__":
    run(attack)
