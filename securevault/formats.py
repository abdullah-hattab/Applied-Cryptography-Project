"""Byte-level formats for every object SecureVault stores or sends.

Section 7.6 asks for a precise format table; the tables below are it, kept
beside the code that must match them.

TWO RULES
1. Every field is fixed-width or length-prefixed.  No delimiters -- a parser
   told the length up front cannot be confused by data containing a separator.
2. Anything covered by a tag or signature is covered AS THE EXACT BYTES ON
   DISK, never a re-encoding.  Each decode_* returns the raw header slice.
"""

from __future__ import annotations

import struct

WIRE_VERSION = 1

MAGIC_CREDENTIAL = b"SVCRED"
MAGIC_KEYSTORE = b"SVKEYS"
MAGIC_KEYRING = b"SVKRNG"
MAGIC_CERTIFICATE = b"SVCERT"
MAGIC_DOCUMENT = b"SVDOC1"
MAGIC_SHARE = b"SVSHRE"
MAGIC_MANIFEST = b"SVMANI"


class FormatError(Exception):
    """Any malformed object.  Carries no detail about which field failed:
    a precise parser error is an oracle (Section 7.6)."""


# ------------------------------------------------------------ tiny codec

class Writer:
    def __init__(self):
        self._parts = []

    def raw(self, data: bytes):
        self._parts.append(data)
        return self

    def u8(self, value: int):
        return self.raw(struct.pack(">B", value))

    def u16(self, value: int):
        return self.raw(struct.pack(">H", value))

    def u32(self, value: int):
        return self.raw(struct.pack(">I", value))

    def u64(self, value: int):
        return self.raw(struct.pack(">Q", value))

    def string8(self, value: str):
        """UTF-8 with a one-byte length: names, up to 255 bytes."""
        encoded = value.encode("utf-8")
        if len(encoded) > 255:
            raise FormatError("string too long")
        return self.u8(len(encoded)).raw(encoded)

    def string16(self, value: str):
        """UTF-8 with a two-byte length: file names."""
        encoded = value.encode("utf-8")
        if len(encoded) > 65535:
            raise FormatError("string too long")
        return self.u16(len(encoded)).raw(encoded)

    def bytes16(self, value: bytes):
        if len(value) > 65535:
            raise FormatError("blob too long")
        return self.u16(len(value)).raw(value)

    def finish(self) -> bytes:
        return b"".join(self._parts)


class Reader:
    def __init__(self, data: bytes):
        self._data = data
        self._offset = 0

    @property
    def offset(self) -> int:
        return self._offset

    def raw(self, count: int) -> bytes:
        if count < 0 or self._offset + count > len(self._data):
            raise FormatError("truncated object")
        chunk = self._data[self._offset:self._offset + count]
        self._offset += count
        return chunk

    def u8(self) -> int:
        return struct.unpack(">B", self.raw(1))[0]

    def u16(self) -> int:
        return struct.unpack(">H", self.raw(2))[0]

    def u32(self) -> int:
        return struct.unpack(">I", self.raw(4))[0]

    def u64(self) -> int:
        return struct.unpack(">Q", self.raw(8))[0]

    def string8(self) -> str:
        try:
            return self.raw(self.u8()).decode("utf-8")
        except UnicodeDecodeError:
            raise FormatError("invalid UTF-8")

    def string16(self) -> str:
        try:
            return self.raw(self.u16()).decode("utf-8")
        except UnicodeDecodeError:
            raise FormatError("invalid UTF-8")

    def bytes16(self) -> bytes:
        return self.raw(self.u16())

    def rest(self) -> bytes:
        chunk = self._data[self._offset:]
        self._offset = len(self._data)
        return chunk

    def expect_magic(self, magic: bytes) -> None:
        if self.raw(len(magic)) != magic:
            raise FormatError("wrong object type")
        if self.u8() != WIRE_VERSION:
            raise FormatError("unsupported wire version")


# =====================================================================
# 1. CREDENTIAL RECORD -- stored by the server, one per user
# =====================================================================
#   size  field
#      6  magic "SVCRED"          1  wire version
#    1+n  username                16  Argon2id salt (NOT secret)
#    1+n  profile name             4  memory cost (KiB)
#      4  time cost                4  parallelism
#     32  verifier = KDF(auth_token, "SV-VERIF-v1")
#      8  created-at (Unix seconds)
#
# The salt is in the clear on purpose: its job is to make each user a separate
# problem, not to be secret.  The parameters are stored so a record made under
# one profile still verifies after the deployment moves to another.

def encode_credential(username, salt, profile, verifier, created_at):
    return (Writer()
            .raw(MAGIC_CREDENTIAL).u8(WIRE_VERSION)
            .string8(username)
            .raw(salt)
            .string8(profile.name)
            .u32(profile.memory_cost).u32(profile.time_cost)
            .u32(profile.parallelism)
            .raw(verifier)
            .u64(created_at)
            .finish())


def decode_credential(data: bytes) -> dict:
    reader = Reader(data)
    reader.expect_magic(MAGIC_CREDENTIAL)
    return {
        "username": reader.string8(),
        "salt": reader.raw(16),
        "profile_name": reader.string8(),
        "memory_cost": reader.u32(),
        "time_cost": reader.u32(),
        "parallelism": reader.u32(),
        "verifier": reader.raw(32),
        "created_at": reader.u64(),
    }


# =====================================================================
# 2. KEYSTORE -- the user's private keys, wrapped, stored by the server
# =====================================================================
#   size  field
#      6  magic "SVKEYS"          1  wire version
#    1+n  username                12  GCM nonce
#   ---- end of AAD ----
#      2  ciphertext length        m  ciphertext = signing(32) || agreement(32)
#     16  GCM tag
#
#   key = vault_key
#
# Stored on the SERVER, not the client's disk -- so a user can log in from any
# machine with only their password (Section 7.3).  The server holds the bytes
# and cannot open them.

def encode_keystore(username, nonce, ciphertext, tag):
    header = (Writer()
              .raw(MAGIC_KEYSTORE).u8(WIRE_VERSION)
              .string8(username)
              .raw(nonce)
              .finish())
    return header + Writer().bytes16(ciphertext).raw(tag).finish(), header


def decode_keystore(data: bytes):
    reader = Reader(data)
    reader.expect_magic(MAGIC_KEYSTORE)
    username = reader.string8()
    nonce = reader.raw(12)
    header = data[:reader.offset]          # exact bytes, used as the AAD
    ciphertext = reader.bytes16()
    tag = reader.raw(16)
    return {"username": username, "nonce": nonce, "header": header,
            "ciphertext": ciphertext, "tag": tag}


# =====================================================================
# 3. CERTIFICATE -- issued by the CA, binds a name to two public keys
# =====================================================================
#   size  field                                    <-- all signed
#      6  magic "SVCERT"           1  wire version
#     16  serial (random)        1+n  subject username
#     65  signing key (ECDSA)     65  agreement key (ECDH)
#      8  issued-at                8  expires-at
#   ---- end of signed body ----
#     64  CA signature (r || s)
#
# TWO KEY PAIRS, NOT ONE: sharing one pair between signing and key agreement
# lets a signing oracle attack the agreement key.  Costs one extra scalar
# multiplication at registration.
#
# The username is INSIDE the signed body, so the server cannot re-label
# Layla's certificate as Mallory's.

def encode_certificate_body(serial, username, signing_key, agreement_key,
                            issued_at, expires_at):
    return (Writer()
            .raw(MAGIC_CERTIFICATE).u8(WIRE_VERSION)
            .raw(serial)
            .string8(username)
            .raw(signing_key)
            .raw(agreement_key)
            .u64(issued_at).u64(expires_at)
            .finish())


def encode_certificate(body: bytes, signature: bytes) -> bytes:
    if len(signature) != 64:
        raise FormatError("bad signature length")
    return body + signature


def decode_certificate(data: bytes) -> dict:
    reader = Reader(data)
    reader.expect_magic(MAGIC_CERTIFICATE)
    serial = reader.raw(16)
    username = reader.string8()
    signing_key = reader.raw(65)
    agreement_key = reader.raw(65)
    issued_at = reader.u64()
    expires_at = reader.u64()
    body = data[:reader.offset]            # exact signed bytes
    signature = reader.raw(64)
    if reader.offset != len(data):
        raise FormatError("trailing bytes after certificate")
    return {"serial": serial, "username": username,
            "signing_key": signing_key, "agreement_key": agreement_key,
            "issued_at": issued_at, "expires_at": expires_at,
            "body": body, "signature": signature}


# =====================================================================
# 4. DOCUMENT OBJECT -- what the server stores for an uploaded file
# =====================================================================
#   size  field                                    <-- header is the GCM AAD
#      6  magic "SVDOC1"           1  wire version
#     16  document id            1+n  owner username
#    2+n  file name              1+n  MIME type
#      8  plaintext size           8  uploaded-at
#     12  GCM nonce
#   ---- end of AAD ----
#      4  ciphertext length        m  ciphertext        16  GCM tag
#
#   key = a fresh 128-bit key, used for this document and no other
#
# METADATA BINDING: the server needs the name, size and owner to list
# documents, so they are in the clear -- and they are the ENTIRE AAD, so
# altering any of them fails the tag.  The document id is inside the AAD too,
# so a ciphertext cannot be moved under a different header.

def encode_document_header(doc_id, owner, filename, mimetype, size,
                           uploaded_at, nonce):
    return (Writer()
            .raw(MAGIC_DOCUMENT).u8(WIRE_VERSION)
            .raw(doc_id)
            .string8(owner)
            .string16(filename)
            .string8(mimetype)
            .u64(size).u64(uploaded_at)
            .raw(nonce)
            .finish())


def encode_document(header: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    return header + Writer().u32(len(ciphertext)).raw(ciphertext).raw(tag).finish()


def decode_document(data: bytes) -> dict:
    reader = Reader(data)
    reader.expect_magic(MAGIC_DOCUMENT)
    doc_id = reader.raw(16)
    owner = reader.string8()
    filename = reader.string16()
    mimetype = reader.string8()
    size = reader.u64()
    uploaded_at = reader.u64()
    nonce = reader.raw(12)
    header = data[:reader.offset]          # exact AAD bytes
    ciphertext = reader.raw(reader.u32())
    tag = reader.raw(16)
    return {"doc_id": doc_id, "owner": owner, "filename": filename,
            "mimetype": mimetype, "size": size, "uploaded_at": uploaded_at,
            "nonce": nonce, "header": header, "ciphertext": ciphertext,
            "tag": tag}


# =====================================================================
# 5. MANIFEST -- the signed statement of authorship.  Never stored in clear.
# =====================================================================
#   size  field                                    <-- ALL of this is signed
#      6  magic "SVMANI"           1  wire version
#     16  manifest id  <- replay identifier
#     16  document id
#    1+n  sender                 1+n  recipient  <- stops forwarding
#     32  BLAKE2b-256 of the PLAINTEXT
#     32  BLAKE2b-256 of the document header
#      8  created-at  <- freshness
#
# RECIPIENT NAME INSIDE THE SIGNATURE: we sign then encrypt, so Omar could
# otherwise re-send Layla's signed manifest to Mallory and pass it off as
# addressed to her.  Mallory's client finds "omar" inside and refuses.
#
# PLAINTEXT HASH, NOT CIPHERTEXT HASH: Layla signs what she means, not how it
# was packaged, so a third party can check the file without any secret.

def encode_manifest(manifest_id, doc_id, sender, recipient, plaintext_hash,
                    metadata_hash, created_at):
    return (Writer()
            .raw(MAGIC_MANIFEST).u8(WIRE_VERSION)
            .raw(manifest_id)
            .raw(doc_id)
            .string8(sender)
            .string8(recipient)
            .raw(plaintext_hash)
            .raw(metadata_hash)
            .u64(created_at)
            .finish())


def decode_manifest(data: bytes) -> dict:
    reader = Reader(data)
    reader.expect_magic(MAGIC_MANIFEST)
    record = {
        "manifest_id": reader.raw(16),
        "doc_id": reader.raw(16),
        "sender": reader.string8(),
        "recipient": reader.string8(),
        "plaintext_hash": reader.raw(32),
        "metadata_hash": reader.raw(32),
        "created_at": reader.u64(),
    }
    if reader.offset != len(data):
        raise FormatError("trailing bytes after manifest")
    return record


# =====================================================================
# 6. SHARE RECORD -- what the server relays from sender to recipient
# =====================================================================
#   size  field                                    <-- header is the GCM AAD
#      6  magic "SVSHRE"           1  wire version
#     16  share id                16  document id
#    1+n  sender                 1+n  recipient
#     12  GCM nonce
#   ---- end of AAD ----
#      2  sealed length
#      m  sealed = manifest_len(2) || manifest || signature(64) || doc key(16)
#     16  GCM tag
#
#   key = KDF(ECDH(sender_priv, recipient_pub), "SV-KEK-v1",
#             context = sender || 0 || recipient || 0 || doc_id)
#
# The names appear twice: in the clear header so the server can route, and
# inside the signed manifest, which is what counts.  The client compares them
# and refuses on a mismatch, so rewriting the header achieves nothing.
#
# What the server sees: two names, two ids, a nonce and a blob.  Not the
# document key, the manifest or the signature -- it cannot even tell whether
# a share is signed.

def encode_share_header(share_id, doc_id, sender, recipient, nonce):
    return (Writer()
            .raw(MAGIC_SHARE).u8(WIRE_VERSION)
            .raw(share_id)
            .raw(doc_id)
            .string8(sender)
            .string8(recipient)
            .raw(nonce)
            .finish())


def encode_share(header: bytes, sealed: bytes, tag: bytes) -> bytes:
    return header + Writer().bytes16(sealed).raw(tag).finish()


def decode_share(data: bytes) -> dict:
    reader = Reader(data)
    reader.expect_magic(MAGIC_SHARE)
    share_id = reader.raw(16)
    doc_id = reader.raw(16)
    sender = reader.string8()
    recipient = reader.string8()
    nonce = reader.raw(12)
    header = data[:reader.offset]
    sealed = reader.bytes16()
    tag = reader.raw(16)
    return {"share_id": share_id, "doc_id": doc_id, "sender": sender,
            "recipient": recipient, "nonce": nonce, "header": header,
            "sealed": sealed, "tag": tag}


def encode_sealed_payload(manifest: bytes, signature: bytes,
                          document_key: bytes) -> bytes:
    return (Writer()
            .bytes16(manifest)
            .raw(signature)
            .raw(document_key)
            .finish())


def decode_sealed_payload(data: bytes) -> dict:
    reader = Reader(data)
    manifest = reader.bytes16()
    signature = reader.raw(64)
    document_key = reader.raw(16)
    if reader.offset != len(data):
        raise FormatError("trailing bytes in sealed payload")
    return {"manifest": manifest, "signature": signature,
            "document_key": document_key}


# =====================================================================
# 7. KEYRING -- the user's document keys and replay history, wrapped
# =====================================================================
#   size  field                                    <-- header is the GCM AAD
#      6  magic "SVKRNG"           1  wire version
#    1+n  username                12  GCM nonce
#   ---- end of AAD ----
#      4  ciphertext length        m  ciphertext        16  GCM tag
#
#   key = vault_key, the same key that wraps the keystore
#
#   plaintext:  2  entry count
#               per entry:  16 doc id | 16 doc key | 1+n origin
#                           2+n manifest | 64 signature
#               2  accepted-manifest count, then 16 bytes each
#
# WHY IT EXISTS: the recipient needs the document key after accepting a share.
# Keeping it server-side, wrapped under vault_key, means a user can log in
# anywhere with only their password.
#
# WHY THE MANIFEST AND SIGNATURE ARE KEPT: non-repudiation is useless if the
# evidence is discarded after checking.  Omar can hand these to a third party
# months later -- the CLI's `verify-receipt` is that third party.
#
# WHY THE ACCEPTED LIST IS HERE: it is the anti-replay record, and keeping it
# inside the encrypted keyring means it follows the user between machines.

def encode_keyring_header(username, nonce):
    return (Writer()
            .raw(MAGIC_KEYRING).u8(WIRE_VERSION)
            .string8(username)
            .raw(nonce)
            .finish())


def encode_keyring(header: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    return header + Writer().u32(len(ciphertext)).raw(ciphertext).raw(tag).finish()


def decode_keyring(data: bytes) -> dict:
    reader = Reader(data)
    reader.expect_magic(MAGIC_KEYRING)
    username = reader.string8()
    nonce = reader.raw(12)
    header = data[:reader.offset]
    ciphertext = reader.raw(reader.u32())
    tag = reader.raw(16)
    return {"username": username, "nonce": nonce, "header": header,
            "ciphertext": ciphertext, "tag": tag}


def encode_keyring_contents(entries: dict, seen_manifests) -> bytes:
    writer = Writer().u16(len(entries))
    for doc_id, entry in sorted(entries.items()):
        (writer.raw(doc_id)
               .raw(entry["document_key"])
               .string8(entry["origin"])
               .bytes16(entry["manifest"])
               .raw(entry["signature"]))
    seen = sorted(seen_manifests)
    writer.u16(len(seen))
    for manifest_id in seen:
        writer.raw(manifest_id)
    return writer.finish()


def decode_keyring_contents(data: bytes) -> tuple:
    reader = Reader(data)
    entries = {}
    for _ in range(reader.u16()):
        doc_id = reader.raw(16)
        entries[doc_id] = {
            "document_key": reader.raw(16),
            "origin": reader.string8(),
            "manifest": reader.bytes16(),
            "signature": reader.raw(64),
        }
    seen = {reader.raw(16) for _ in range(reader.u16())}
    if reader.offset != len(data):
        raise FormatError("trailing bytes in keyring")
    return entries, seen