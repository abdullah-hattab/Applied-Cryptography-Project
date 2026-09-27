"""Attack 5: a deliberately WEAKENED build, and an attack that beats it.
"""

from harness import banner, result, run, step
from securevault import formats, params
from securevault.client import Client
from securevault.crypto import gcm

FIXED_KEY = bytes.fromhex("00112233445566778899aabbccddeeff")
FIXED_NONCE = bytes.fromhex("000000000000000000000001")


class DeliberatelyWeakClient(Client):

    def upload(self, filename, plaintext, mimetype="application/octet-stream"):
        import os
        import time
        from securevault.crypto.blake2b import blake2b

        document_key = FIXED_KEY          # <-- THE BUG: not fresh per document
        nonce = FIXED_NONCE               # <-- THE BUG: not fresh per message
        doc_id = os.urandom(16)

        header = formats.encode_document_header(
            doc_id=doc_id, owner=self.username, filename=filename,
            mimetype=mimetype, size=len(plaintext),
            uploaded_at=int(time.time()), nonce=nonce)
        ciphertext, tag = gcm.encrypt(document_key, nonce, plaintext, header)
        self.server.put_document(
            self._session, formats.encode_document(header, ciphertext, tag))

        entries, seen = self._load_keyring()
        entries[doc_id] = {"document_key": document_key,
                           "origin": self.username,
                           "manifest": b"", "signature": b"\x00" * 64}
        self._save_keyring(entries, seen)
        return doc_id


PUBLIC = (b"MEETING AGENDA - open to all staff\n"
          b"1. Budget review\n2. Hiring update\n3. Any other business\n")
SECRET = (b"SALARY REVIEW - strictly confidential\n"
          b"Layla Haddad ..... 9,400 ILS/month\n"
          b"Omar Nasser ...... 8,150 ILS/month\n")


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _run_against(world, client_class, label):
    print(f"\n  ---- {label} ----")
    client = client_class(world.server, world.ca_public, world.ca)
    name = "weakuser" if client_class is DeliberatelyWeakClient else "gooduser"
    client.register(name, "a-long-enough-password", params.DEMO)

    public_id = client.upload("agenda.txt", PUBLIC)
    secret_id = client.upload("salaries.txt", SECRET)

    public_document = formats.decode_document(
        world.server.raw_object("documents", public_id))
    secret_document = formats.decode_document(
        world.server.raw_object("documents", secret_id))

    print(f"     nonce on document 1: {public_document['nonce'].hex()}")
    print(f"     nonce on document 2: {secret_document['nonce'].hex()}")

    # The attacker is the server.  They hold both ciphertexts, and they
    # happen to know the contents of the first -- it is a public notice.
    recovered = _xor(
        _xor(public_document["ciphertext"], secret_document["ciphertext"]),
        PUBLIC)

    print()
    print("     The attacker computes  C1 XOR C2 XOR P1  and reads:")
    print("     " + "-" * 56)
    for line in recovered.split(b"\n"):
        try:
            rendered = line.decode("utf-8")
        except UnicodeDecodeError:
            rendered = repr(line)
        print(f"     | {rendered}")
    print("     " + "-" * 56)

    return recovered == SECRET[:len(recovered)]


def attack(world):
    banner("Attack 5: nonce reuse -- a weakened build, broken")

    print("\n  The victim uploads two documents: a public meeting agenda,")
    print("  and a confidential salary review.  The attacker is the server,")
    print("  so it holds both ciphertexts, and it already knows the agenda")
    print("  because the agenda is public.")

    step("Against the DELIBERATELY WEAKENED build (one fixed key and nonce)")
    broken = _run_against(world, DeliberatelyWeakClient, "weak build")
    if broken:
        result(True, "the confidential document was recovered in full")
        print("     Why: CTR mode encrypts by XOR-ing a keystream.  The same")
        print("     key and nonce give the SAME keystream, so")
        print("         C1 XOR C2 = (P1 XOR S) XOR (P2 XOR S) = P1 XOR P2")
        print("     and the keystream cancels out completely.  Knowing P1")
        print("     yields P2 exactly.  No key was broken and no tag was")
        print("     forged -- the arithmetic simply gave it away.")
        print()
        print("     It gets worse than confidentiality: a repeated nonce in")
        print("     GCM also allows the authentication subkey H to be")
        print("     recovered by solving a polynomial over GF(2^128) (the")
        print("     'forbidden attack', Joux 2006), after which the attacker")
        print("     can forge tags at will.  We did not implement that part;")
        print("     the plaintext recovery above already makes the point.")

    step("Against the CORRECT build (a fresh key per document)")
    broken = _run_against(world, Client, "correct build")
    if broken:
        result(True, "the confidential document was recovered")
    else:
        result(False, "the output is noise -- nothing was recovered")
        print("     Why: the two documents are encrypted under DIFFERENT")
        print("     keys, so the keystreams are unrelated and nothing")
        print("     cancels.  C1 XOR C2 is just two independent keystreams")
        print("     XORed together, which carries no information about")
        print("     either plaintext.")
        print()
        print("     Note what the fix is NOT: we did not add a check, or a")
        print("     counter, or a database of used nonces.  We made the")
        print("     dangerous state unreachable -- a key that encrypts")
        print("     exactly one message cannot repeat a pair, even if the")
        print("     process crashes, restarts, or runs twice at once.")


if __name__ == "__main__":
    run(attack)
