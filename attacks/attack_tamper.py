"""Attacks 2 and 3: tampering with the ciphertext and with the metadata.

"""

from harness import banner, result, run, step
from securevault import formats
from securevault.client import ClientError


def attack(world):
    banner("Attack 2 & 3: tampering with stored objects")

    doc_id = world.share_a_document()
    world.omar.accept_shares()
    print(f"\n  Layla uploaded and shared a document ({doc_id.hex()[:16]}...)")
    print("  Omar has accepted the share and can read it:")
    print(f"    {world.omar.retrieve(doc_id).plaintext[:48]!r} ...")

    original = world.server.raw_object("documents", doc_id)

    # ---------------------------------------------------------------- 2
    step("Attack 2: flip ONE BIT of the ciphertext")
    parsed = formats.decode_document(original)
    offset = len(parsed["header"]) + 4
    tampered = bytearray(original)
    tampered[offset] ^= 0x01
    print(f"     byte {offset}: 0x{original[offset]:02x} -> "
          f"0x{tampered[offset]:02x}")
    world.server.storage.put("documents", doc_id, bytes(tampered))

    try:
        world.omar.retrieve(doc_id)
        result(True, "the client accepted a modified document")
    except ClientError as error:
        result(False, f"the client refused it: {error.detail}")
        print("     Why: the GCM tag is computed over the ciphertext, so any")
        print("     change makes the tag mismatch.  The plaintext is never")
        print("     released to the caller -- decryption happens only after")
        print("     the tag verifies.")

    world.server.storage.put("documents", doc_id, original)

    # ---------------------------------------------------------------- 3
    step("Attack 3: rename the file in the metadata (which is NOT encrypted)")
    print("     The server can read 'thesis-draft.pdf' in the clear --")
    print("     it needs to, to list documents.  Can it change it?")
    print()
    print("     The replacement is the SAME LENGTH on purpose.  A different")
    print("     length would break the length prefix and the parser would")
    print("     refuse before any cryptography ran -- which proves nothing")
    print("     about the tag.  Keeping the object perfectly well-formed")
    print("     forces the authentication check to be what catches it.")
    tampered = original.replace(b"thesis-draft.pdf", b"thesis-final.pdf")
    assert tampered != original and len(tampered) == len(original)
    world.server.storage.put("documents", doc_id, tampered)

    try:
        world.omar.retrieve(doc_id)
        result(True, "the client accepted altered metadata")
    except ClientError as error:
        result(False, f"the client refused it: {error.detail}")
        print("     Note WHICH check fired.  There are TWO independent")
        print("     mechanisms binding this metadata, and for a SHARED")
        print("     document the outer one fires first:")
        print("       1. Layla's signed manifest commits to a hash of the")
        print("          metadata header, and retrieve() checks that before")
        print("          it decrypts anything.")
        print("       2. The metadata header is also the ASSOCIATED DATA of")
        print("          the GCM encryption, so the tag covers it too.")
        print("     The next step strips away the first to expose the second.")

    step("Attack 3 again, on a document with NO signed manifest")
    print("     Layla's own upload has no manifest -- there is nobody to")
    print("     attest that she wrote her own file.  So mechanism 1 does not")
    print("     apply and the GCM tag has to carry the weight alone.")
    own_id = world.layla.upload("private-notes.txt", b"my own private notes")
    own = world.server.raw_object("documents", own_id)
    tampered_own = own.replace(b"private-notes.txt", b"public-notes.txt.")
    assert tampered_own != own and len(tampered_own) == len(own)
    world.server.storage.put("documents", own_id, tampered_own)

    try:
        world.layla.retrieve(own_id)
        result(True, "the client accepted altered metadata")
    except ClientError as error:
        result(False, f"the client refused it: {error.detail}")
        print("     Mechanism 2 on its own, with nothing else helping:")
        print("     the metadata is readable by the server and still")
        print("     unforgeable, because it is the AAD of the encryption.")

    step("Attack 3a: the same rename, but with a DIFFERENT length")
    tampered = original.replace(b"thesis-draft.pdf", b"x.jpg")
    world.server.storage.put("documents", doc_id, tampered)
    try:
        world.omar.retrieve(doc_id)
        result(True, "the client accepted a malformed object")
    except ClientError as error:
        result(False, f"the client refused it: {error.detail}")
        print("     A different failure mode: the length prefix no longer")
        print("     matches, so the parser rejects it.  Both paths refuse,")
        print("     and both report the same opaque error to the caller.")

    world.server.storage.put("documents", doc_id, original)

    # -------------------------------------------------- moving a ciphertext
    step("Attack 3b: move the ciphertext under a DIFFERENT document's header")
    other_id = world.layla.upload("decoy.txt", b"a harmless decoy file")
    other = world.server.raw_object("documents", other_id)
    other_parsed = formats.decode_document(other)

    frankenstein = formats.encode_document(
        other_parsed["header"], parsed["ciphertext"], parsed["tag"])
    world.server.storage.put("documents", other_id, frankenstein)
    print("     The secret ciphertext is now filed under the decoy's header.")

    try:
        world.layla.retrieve(other_id)
        result(True, "the client accepted a relocated ciphertext")
    except ClientError as error:
        result(False, f"the client refused it: {error.detail}")
        print("     Why: the document id and nonce are inside the AAD, so a")
        print("     ciphertext cannot be detached from the header it was")
        print("     authenticated with.  This is the 'moved to a different")
        print("     document' case named in Section 6.")


if __name__ == "__main__":
    run(attack)
