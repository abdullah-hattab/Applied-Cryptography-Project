"""Command-line client for SecureVault.
"""

from __future__ import annotations

import argparse
import os
import sys

from . import formats, params
from .ca import CertificateAuthority
from .client import Client, ClientError, Receipt, verify_receipt
from .crypto import P256
from .crypto.kdf import format_fingerprint
from .server import Server, ServerError

DEFAULT_ROOT = "vault-storage"


def _paths(root):
    return {"ca": os.path.join(root, "ca"),
            "server": os.path.join(root, "server"),
            "trust": os.path.join(root, "trust", "ca-public.key")}


def _load_trust_anchor(root):
    """Load the CA public key from the client's trust store.
    """
    path = _paths(root)["trust"]
    try:
        with open(path, "rb") as handle:
            return P256.decode_point(handle.read())
    except FileNotFoundError:
        raise SystemExit(f"no trust anchor at {path} -- run `init` first")


def _open(root, need_ca=False):
    ca_public = _load_trust_anchor(root)
    server = Server(_paths(root)["server"], ca_public)
    authority = CertificateAuthority(_paths(root)["ca"]) if need_ca else None
    return Client(server, ca_public, authority), server


def _profile(name):
    if name not in params.PROFILES:
        raise SystemExit(f"unknown profile {name}; choose from "
                         f"{', '.join(params.PROFILES)}")
    return params.PROFILES[name]


# ----------------------------------------------------------------- commands

def cmd_init(args):
    paths = _paths(args.root)
    authority = CertificateAuthority(paths["ca"])
    os.makedirs(os.path.dirname(paths["trust"]), exist_ok=True)
    with open(paths["trust"], "wb") as handle:
        handle.write(authority.export_trust_anchor())
    Server(paths["server"], P256.decode_point(authority.export_trust_anchor()))

    print(f"certificate authority initialised in {paths['ca']}")
    print(f"trust anchor written to      {paths['trust']}")
    print(f"server storage in            {paths['server']}")
    print()
    print("CA public key fingerprint:")
    print(f"  {format_fingerprint(authority.export_trust_anchor())}")
    print()
    print("This fingerprint is the value that must reach users out of band.")


def cmd_register(args):
    client, _ = _open(args.root, need_ca=True)
    profile = _profile(args.profile)
    print(f"deriving key material with Argon2id ({profile!r}) ...")
    client.register(args.user, args.password, profile)
    print(f"registered {args.user}")
    print(f"your key fingerprint: {client.fingerprint_of(args.user)}")


def cmd_fingerprint(args):
    client, _ = _open(args.root)
    client.login(args.user, args.password)
    target = args.of or args.user
    print(f"{target}: {client.fingerprint_of(target)}")
    print()
    print("Read this aloud to the other person and compare, character by")
    print("character.  If it differs, someone is between you -- stop.")


def cmd_upload(args):
    client, _ = _open(args.root)
    client.login(args.user, args.password)
    with open(args.file, "rb") as handle:
        data = handle.read()
    doc_id = client.upload(os.path.basename(args.file), data, args.mimetype)
    print(f"uploaded {os.path.basename(args.file)} ({len(data)} bytes)")
    print(f"document id: {doc_id.hex()}")


def cmd_share(args):
    client, _ = _open(args.root)
    client.login(args.user, args.password)
    client.share(bytes.fromhex(args.doc), args.to)
    print(f"shared {args.doc} with {args.to}")


def cmd_inbox(args):
    client, _ = _open(args.root)
    client.login(args.user, args.password)
    accepted = client.accept_shares()
    for doc_id, sender in accepted:
        print(f"accepted {doc_id.hex()} from {sender}")
    for reason in getattr(client, "last_rejections", []):
        print(f"REFUSED a share: {reason}")
    if not accepted and not getattr(client, "last_rejections", []):
        print("nothing new")


def cmd_list(args):
    client, _ = _open(args.root)
    client.login(args.user, args.password)
    documents = client.list_documents()
    if not documents:
        print("no documents")
        return
    print(f"{'document id':<34}{'name':<24}{'size':>9}  origin")
    for record in documents:
        origin = record["origin"] or "-"
        print(f"{record['doc_id'].hex():<34}{record['filename']:<24}"
              f"{record['size']:>9}  {origin}")


def cmd_get(args):
    client, _ = _open(args.root)
    client.login(args.user, args.password)
    try:
        receipt = client.retrieve(bytes.fromhex(args.doc))
    except ClientError as error:
        # The user sees the reason for their OWN failed retrieval, which is
        # not an oracle: they already hold the key material involved.  What
        # never travels over the network is a message that distinguishes
        # these cases to a remote party.
        print(f"REFUSED: {error.detail}", file=sys.stderr)
        raise SystemExit(1)

    with open(args.out, "wb") as handle:
        handle.write(receipt.plaintext)
    print(f"wrote {len(receipt.plaintext)} bytes to {args.out}")
    if receipt.attested:
        print(f"this document was produced by: {receipt.sender}")
        print(f"signed manifest addressed to:  {receipt.recipient}")
        print("the signature verifies against their CA-issued certificate")
        if args.receipt:
            _write_receipt(receipt, args.receipt)
            print(f"evidence bundle written to {args.receipt}")
    else:
        print("this is your own upload -- no sender attestation, by design")


def _write_receipt(receipt, path):
    """Write the evidence bundle a third party can check."""
    blob = (formats.Writer()
            .bytes16(receipt.manifest_bytes)
            .raw(receipt.signature)
            .bytes16(receipt.certificate)
            .finish())
    with open(path, "wb") as handle:
        handle.write(blob)
    with open(path + ".document", "wb") as handle:
        handle.write(receipt.plaintext)


def cmd_inspect(args):
    """Show what the server actually stores.  Demonstration requirements 2
    and 3 ask for exactly this."""
    _, server = _open(args.root)

    # Keys are usernames in some collections and raw identifiers in others.
    # Document and share identifiers are random bytes, so they are given on
    # the command line as hex and converted here.
    if args.collection in ("documents", "acl"):
        key = bytes.fromhex(args.key)
    elif args.collection == "shares":
        recipient, _, share_id = args.key.partition(":")
        if not share_id:
            matches = [k for k in server.storage.list_keys("shares")
                       if k.startswith(recipient.encode() + b"/")]
            if not matches:
                raise SystemExit(f"no shares addressed to {recipient}")
            print(f"{len(matches)} share(s) addressed to {recipient}; "
                  f"showing the first")
            key = matches[0]
        else:
            key = recipient.encode() + b"/" + bytes.fromhex(share_id)
    else:
        key = args.key

    blob = server.raw_object(args.collection, key)
    if blob is None:
        raise SystemExit("no such object")

    path = server.raw_path(args.collection, key)
    print(f"file: {path}")
    print(f"size: {len(blob)} bytes")
    print()

    if args.collection == "credentials":
        record = formats.decode_credential(blob)
        print("parsed credential record:")
        print(f"  username     {record['username']}")
        print(f"  salt         {record['salt'].hex()}   (not secret)")
        print(f"  argon2id     m={record['memory_cost']} KiB  "
              f"t={record['time_cost']}  p={record['parallelism']}  "
              f"({record['profile_name']})")
        print(f"  verifier     {record['verifier'].hex()}")
        print()
        print("  The verifier is BLAKE2b of an Argon2id output.  Recovering")
        print("  the password from it means guessing the password and paying")
        print("  the full Argon2id cost for every guess.")

    print()
    print("raw bytes:")
    _hexdump(blob[:args.bytes])
    if len(blob) > args.bytes:
        print(f"... {len(blob) - args.bytes} more bytes")


def _hexdump(data, width=16):
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"  {offset:08x}  {hexpart}  |{text}|")


def cmd_verify_receipt(args):
    """The third party's tool.  Needs the CA public key and nothing else --
    no password, no session, no trust in whoever handed over the bundle."""
    ca_public = _load_trust_anchor(args.root)
    with open(args.receipt, "rb") as handle:
        reader = formats.Reader(handle.read())
    manifest_bytes = reader.bytes16()
    signature = reader.raw(64)
    certificate = reader.bytes16()
    with open(args.receipt + ".document", "rb") as handle:
        plaintext = handle.read()

    receipt = Receipt(manifest_bytes, signature, certificate, plaintext, None)
    try:
        manifest = verify_receipt(receipt, ca_public)
    except ClientError as error:
        print(f"NOT VERIFIED: {error.detail}")
        raise SystemExit(1)

    print("VERIFIED")
    print(f"  produced by      {manifest['sender']}")
    print(f"  addressed to     {manifest['recipient']}")
    print(f"  document id      {manifest['doc_id'].hex()}")
    print(f"  signed at        {manifest['created_at']}")
    print()
    print("  Checked: the CA signed a certificate binding that name to a")
    print("  public key; that key signed this manifest; this manifest commits")
    print("  to the hash of the document file supplied alongside it.")


def cmd_change_password(args):
    client, _ = _open(args.root)
    client.login(args.user, args.password)
    client.change_password(args.password, args.new_password,
                           _profile(args.profile))
    print("password changed")
    print("your key pair, certificate and fingerprint are unchanged,")
    print("and every document shared with you still opens")


# -------------------------------------------------------------------- main

def build_parser():
    parser = argparse.ArgumentParser(
        prog="securevault",
        description="Encrypted document exchange over an untrusted server")
    parser.add_argument("--root", default=DEFAULT_ROOT,
                        help="storage directory (the simulated network)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add(name, function, *arguments):
        sub = subparsers.add_parser(name)
        sub.set_defaults(function=function)
        for args, kwargs in arguments:
            sub.add_argument(*args, **kwargs)
        return sub

    user = (("--user",), {"required": True})
    password = (("--password",), {"required": True})
    profile = (("--profile",), {"default": "demo",
                                "help": "demo or production"})

    add("init", cmd_init)
    add("register", cmd_register, user, password, profile)
    add("fingerprint", cmd_fingerprint, user, password,
        (("--of",), {"help": "whose fingerprint to show"}))
    add("upload", cmd_upload, user, password,
        (("--file",), {"required": True}),
        (("--mimetype",), {"default": "application/octet-stream"}))
    add("share", cmd_share, user, password,
        (("--doc",), {"required": True}), (("--to",), {"required": True}))
    add("inbox", cmd_inbox, user, password)
    add("list", cmd_list, user, password)
    add("get", cmd_get, user, password,
        (("--doc",), {"required": True}), (("--out",), {"required": True}),
        (("--receipt",), {"help": "also write an evidence bundle here"}))
    add("inspect", cmd_inspect,
        (("--collection",), {"required": True,
                             "help": "credentials, documents, shares, "
                                     "keystores, keyrings, certificates"}),
        (("--key",), {"required": True}),
        (("--bytes",), {"type": int, "default": 128}))
    add("verify-receipt", cmd_verify_receipt,
        (("--receipt",), {"required": True}))
    add("change-password", cmd_change_password, user, password, profile,
        (("--new-password",), {"required": True}))

    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        args.function(args)
    except (ClientError, ServerError) as error:
        detail = getattr(error, "detail", str(error))
        print(f"failed: {detail}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
