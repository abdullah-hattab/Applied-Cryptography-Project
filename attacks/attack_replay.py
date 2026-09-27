"""Attack 4: replaying a captured object."""

import os
import time

from harness import banner, result, run, step
from securevault import formats, params


def attack(world):
    banner("Attack 4: replay")

    doc_id = world.share_a_document()
    print(f"\n  Layla shared a document with Omar.")
    print("  The attacker records the share record off the wire before Omar")
    print("  ever sees it.")

    key = [k for k in world.server.storage.list_keys("shares")
           if k.startswith(b"omar/")][0]
    captured = world.server.raw_object("shares", key)
    print(f"  captured {len(captured)} bytes")

    step("Omar accepts the share normally")
    accepted = world.omar.accept_shares()
    print(f"     accepted: {[(d.hex()[:16], s) for d, s in accepted]}")

    # ---------------------------------------------------------------- 4a
    step("4a: replay the captured object IMMEDIATELY, unmodified")
    print("     Well inside the freshness window, so the timestamp check")
    print("     cannot help here.  Byte-for-byte identical, so every")
    print("     signature and tag on it is still perfectly valid.")
    world.server.storage.put("shares", b"omar/" + os.urandom(16), captured)

    accepted = world.omar.accept_shares()
    if accepted:
        result(True, "the replayed share was accepted again")
    else:
        result(False, f"refused: {world.omar.last_rejections}")
        print("     Why: the manifest identifier inside the signed region has")
        print("     been seen before.  Omar's client keeps every identifier")
        print("     it has ever accepted, inside his encrypted keyring, so")
        print("     the record follows him between machines.")
        print("     A timestamp ALONE could not catch this -- the object is")
        print("     seconds old.  This is why we have both mechanisms.")

    # ---------------------------------------------------------------- 4b
    step("4b: replay it a day later against a user who never saw it")
    fresh_world_time = int(time.time()) + 24 * 3600
    world.server.storage.put("shares", b"omar/" + os.urandom(16), captured)
    accepted = world.omar.accept_shares(now=fresh_world_time)
    if accepted:
        result(True, "a day-old share was accepted")
    else:
        result(False, f"refused: {world.omar.last_rejections}")
        print("     Why: the signed timestamp is older than the freshness")
        print("     window.  This is the mechanism that bounds how long the")
        print("     accepted-identifier list has to grow -- without it, the")
        print("     list would have to be kept forever.")

    # ---------------------------------------------------------------- 4c
    step("4c: rewrite the timestamp to make it look fresh")
    parsed = formats.decode_share(captured)
    print("     The timestamp is inside the ENCRYPTED, SIGNED manifest.")
    print("     The attacker cannot read it, let alone change it.  The best")
    print("     they can do is corrupt bytes at random and hope.")
    corrupted = bytearray(captured)
    corrupted[len(parsed["header"]) + 20] ^= 0xFF
    world.server.storage.put("shares", b"omar/" + os.urandom(16),
                             bytes(corrupted))
    accepted = world.omar.accept_shares()
    if accepted:
        result(True, "a corrupted share was accepted")
    else:
        result(False, f"refused: {world.omar.last_rejections}")


if __name__ == "__main__":
    run(attack)
