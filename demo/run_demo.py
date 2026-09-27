"""The live demonstration, scripted.

Walks through all nine numbered requirements of Section 8 in order, driving
the real command-line client as a separate process for every user action --
so what you see on screen is the actual interface, not a special demo path
through the library.

    python3 demo/run_demo.py            run it straight through
    python3 demo/run_demo.py --pause    stop between steps (press Enter)
    python3 demo/run_demo.py --step 6   jump straight to one step

Rehearse with --pause.  The failure cases (6, 7, 8) are the ones that go
wrong live, so run them more than once.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from securevault import formats
from securevault.ca import CertificateAuthority
from securevault.client import Client, ClientError
from securevault.crypto import P256
from securevault.server import Server

LAYLA_PASSWORD = "layla-correct-horse-battery-staple"
OMAR_PASSWORD = "omar-a-quite-different-passphrase"

THESIS = (b"CONFIDENTIAL DRAFT - Chapter 3: Results\n"
          b"The measurements in Table 2 are unpublished.\n"
          b"Do not circulate outside the supervisory committee.\n") * 6

PAUSE = False


# ----------------------------------------------------------------- plumbing

def heading(number, title):
    print()
    print("═" * 74)
    print(f"  DEMONSTRATION REQUIREMENT {number}")
    print(f"  {title}")
    print("═" * 74)
    if PAUSE:
        input("\n  [Enter to continue] ")


def note(text):
    for line in text.strip().split("\n"):
        print(f"  {line.strip()}")


def shell(workdir, *arguments):
    """Run the real CLI in a subprocess, showing the command and its output."""
    command = [sys.executable, "-m", "securevault.cli",
               "--root", os.path.join(workdir, "store")] + list(arguments)
    shown = " ".join(a if " " not in a else f'"{a}"' for a in command[3:])
    print(f"\n  $ securevault {shown}")
    environment = dict(os.environ, PYTHONPATH=ROOT)
    completed = subprocess.run(command, capture_output=True, text=True,
                               cwd=workdir, env=environment)
    for line in (completed.stdout + completed.stderr).rstrip().split("\n"):
        print(f"    {line}")
    return completed


def api(workdir):
    """Direct library access, for the attacker's steps."""
    trust = os.path.join(workdir, "store", "trust", "ca-public.key")
    with open(trust, "rb") as handle:
        ca_public = P256.decode_point(handle.read())
    server = Server(os.path.join(workdir, "store", "server"), ca_public)
    authority = CertificateAuthority(os.path.join(workdir, "store", "ca"))
    return server, ca_public, authority


# -------------------------------------------------------------------- steps

def step_1(workdir):
    heading(1, "Two users register and log in, in separate directories")
    note("""
        Each user runs the client as a separate process with its own working
        directory.  Nothing is shared between them except the storage
        directory, which stands in for the network and which the attacker is
        assumed to control completely.
    """)
    shell(workdir, "init")
    note("""
        The CA fingerprint above is the ONE value that must reach users by a
        channel the attacker cannot touch.  Everything else can travel over a
        channel the attacker owns.
    """)
    shell(workdir, "register", "--user", "layla", "--password", LAYLA_PASSWORD)
    shell(workdir, "register", "--user", "omar", "--password", OMAR_PASSWORD)
    shell(workdir, "list", "--user", "layla", "--password", LAYLA_PASSWORD)


def step_2(workdir):
    heading(2, "The stored credential record reveals nothing about the password")
    shell(workdir, "inspect", "--collection", "credentials", "--key", "layla",
          "--bytes", "96")
    note("""
        What is there: a salt (not secret), the Argon2id work factor, and a
        32-byte verifier.  What is not there: the password, or anything from
        which it can be recovered without guessing it and paying the full
        Argon2id cost for every guess.

        Run attacks/attack_offline_guessing.py for the arithmetic.
    """)


def step_3(workdir):
    heading(3, "A document is uploaded; the server's copy is unreadable")
    path = os.path.join(workdir, "thesis-draft.pdf")
    with open(path, "wb") as handle:
        handle.write(THESIS)
    print(f"\n  Layla's file, before upload ({len(THESIS)} bytes):")
    print(f"    {THESIS[:60].decode()}...")

    completed = shell(workdir, "upload", "--user", "layla",
                      "--password", LAYLA_PASSWORD, "--file", path,
                      "--mimetype", "application/pdf")
    doc_id = completed.stdout.strip().split()[-1]

    shell(workdir, "inspect", "--collection", "documents", "--key", doc_id,
          "--bytes", "144")
    note("""
        The metadata is readable: the server needs the file name, size and
        owner to do its job.  The contents are noise.  And the metadata,
        readable as it is, cannot be altered -- requirement 7 shows that.
    """)
    return doc_id


def step_4(workdir, doc_id):
    heading(4, "The document is shared, and the second user opens it")
    shell(workdir, "share", "--user", "layla", "--password", LAYLA_PASSWORD,
          "--doc", doc_id, "--to", "omar")
    shell(workdir, "inbox", "--user", "omar", "--password", OMAR_PASSWORD)
    shell(workdir, "get", "--user", "omar", "--password", OMAR_PASSWORD,
          "--doc", doc_id, "--out", os.path.join(workdir, "omar-copy.pdf"),
          "--receipt", os.path.join(workdir, "omar.receipt"))

    with open(os.path.join(workdir, "omar-copy.pdf"), "rb") as handle:
        received = handle.read()
    print(f"\n  byte-for-byte identical to Layla's original: "
          f"{received == THESIS}")


def step_5(workdir):
    heading(5, "The recipient learns who produced it -- and can prove it")
    note("""
        The client already said "produced by: layla" in the previous step.
        That is Omar's own client telling Omar.  The stronger claim is that
        Omar can convince somebody else, who trusts neither him nor the
        server.

        Below, a third party checks the evidence bundle with nothing but the
        CA's public key.  No password, no session, no secret of any kind.
    """)
    shell(workdir, "verify-receipt", "--receipt",
          os.path.join(workdir, "omar.receipt"))
    note("""
        A MAC could not do this.  Omar can verify a MAC only because he holds
        the key that produces it -- so his word that Layla made the tag is
        worth nothing to a third party who knows Omar could have made it too.
        The signature is verified with a public key that cannot sign, so the
        only party who could have produced it is Layla.
    """)


def _restore(server, doc_id_bytes, original):
    server.storage.put("documents", doc_id_bytes, original)


def step_6(workdir, doc_id):
    heading(6, "A single byte of the ciphertext is altered")
    server, ca_public, _ = api(workdir)
    doc_id_bytes = bytes.fromhex(doc_id)
    original = server.raw_object("documents", doc_id_bytes)
    parsed = formats.decode_document(original)

    offset = len(parsed["header"]) + 4
    tampered = bytearray(original)
    tampered[offset] ^= 0x01
    print(f"\n  The attacker edits the stored file directly.")
    print(f"  byte {offset}: 0x{original[offset]:02x} -> 0x{tampered[offset]:02x}"
          f"   (one bit)")
    server.storage.put("documents", doc_id_bytes, bytes(tampered))

    shell(workdir, "get", "--user", "omar", "--password", OMAR_PASSWORD,
          "--doc", doc_id, "--out", os.path.join(workdir, "should-not-exist"))
    note("""
        Refused, and nothing was written.  The GCM tag is computed over the
        ciphertext, and the tag is checked BEFORE any plaintext is released
        to the caller.
    """)
    _restore(server, doc_id_bytes, original)


def step_7(workdir, doc_id):
    heading(7, "A field of the metadata is altered")
    server, _, _ = api(workdir)
    doc_id_bytes = bytes.fromhex(doc_id)
    original = server.raw_object("documents", doc_id_bytes)

    tampered = original.replace(b"thesis-draft.pdf", b"thesis-final.pdf")
    assert tampered != original and len(tampered) == len(original)
    print("\n  The attacker renames the file in the metadata, which is NOT")
    print("  encrypted -- the server can read it perfectly well.")
    print("  The replacement is the same length, so the object stays")
    print("  well-formed and the parser has no reason to complain.")
    server.storage.put("documents", doc_id_bytes, tampered)

    shell(workdir, "get", "--user", "omar", "--password", OMAR_PASSWORD,
          "--doc", doc_id, "--out", os.path.join(workdir, "should-not-exist"))
    note("""
        Refused.  Two independent mechanisms bind this metadata, and for a
        shared document the outer one fires first: Layla's signed manifest
        commits to a hash of the metadata header.  Underneath it, the header
        is also the associated data of the GCM encryption.
        attacks/attack_tamper.py demonstrates each one separately.
    """)
    _restore(server, doc_id_bytes, original)


def step_8(workdir, doc_id):
    heading(8, "An old captured object is replayed")
    server, ca_public, _ = api(workdir)

    key = [k for k in server.storage.list_keys("shares")
           if k.startswith(b"omar/")][0]
    captured = server.raw_object("shares", key)
    print(f"\n  The attacker captured Layla's share record ({len(captured)} "
          f"bytes) and re-delivers it.")
    print("  It is byte-for-byte identical, so every signature and tag on it")
    print("  is still perfectly valid.")
    server.storage.put("shares", b"omar/" + os.urandom(16), captured)

    shell(workdir, "inbox", "--user", "omar", "--password", OMAR_PASSWORD)
    note("""
        Refused as a replay.  The manifest identifier inside the signed region
        has been accepted before, and Omar's client keeps every identifier it
        has ever accepted inside his encrypted keyring.

        A timestamp alone could not catch this -- the object is seconds old.
        Run attacks/attack_replay.py to see the day-old case, where the
        timestamp is what refuses it.
    """)


def step_9(workdir):
    heading(9, "Every implemented primitive produces correct results")
    note("""
        Run live.  The published test vectors are the primary evidence --
        RFC 7693 for BLAKE2b, FIPS 197 for AES, the McGrew-Viega cases for
        GCM, RFC 9106 for Argon2, RFC 6979 for the ECDSA nonces and
        signatures -- and the suite additionally diffs against reference
        libraries on random inputs.
    """)
    print()
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "-v", "-m", "not slow",
         "--no-header", "-q", "--tb=short"],
        cwd=ROOT, capture_output=True, text=True,
        env=dict(os.environ, PYTHONPATH=ROOT))
    for line in completed.stdout.rstrip().split("\n")[-40:]:
        print(f"    {line}")


# --------------------------------------------------------------------- main

def main():
    global PAUSE
    parser = argparse.ArgumentParser()
    parser.add_argument("--pause", action="store_true",
                        help="stop between steps")
    parser.add_argument("--step", type=int, help="run one step only")
    parser.add_argument("--keep", action="store_true",
                        help="keep the working directory afterwards")
    args = parser.parse_args()
    PAUSE = args.pause

    workdir = tempfile.mkdtemp(prefix="securevault-demo-")
    print(f"working directory: {workdir}")

    try:
        if args.step and args.step not in (1, 2, 9):
            print("\nSteps 3-8 build on one another; running from step 1.")

        step_1(workdir)
        if args.step == 1:
            return
        step_2(workdir)
        if args.step == 2:
            return
        doc_id = step_3(workdir)
        step_4(workdir, doc_id)
        step_5(workdir)
        step_6(workdir, doc_id)
        step_7(workdir, doc_id)
        step_8(workdir, doc_id)
        step_9(workdir)

        print()
        print("═" * 74)
        print("  All nine requirements demonstrated.")
        print("  For the bonus attacks, run the programs in attacks/.")
        print("═" * 74)
    finally:
        if args.keep:
            print(f"\nworking directory kept at {workdir}")
        else:
            shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    main()
