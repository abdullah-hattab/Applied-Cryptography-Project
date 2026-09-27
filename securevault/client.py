"""The SecureVault client -- every cryptographic decision in the system.

All key material is created here, used here, and destroyed here.  The server
is a store and a relay; if this file is correct, the server's honesty is
irrelevant, which is the whole design.

THE LIFE OF A DOCUMENT, end to end, since Section 10 asks for it:

  UPLOAD
    1. Generate a fresh 128-bit document key.  Used for this document and no
       other, ever -- which is what makes GCM nonce reuse impossible.
    2. Build the metadata header: id, owner, file name, type, size, time,
       and a fresh 96-bit nonce.
    3. Encrypt the file with AES-128-GCM under the document key, with the
       whole metadata header as associated data.
    4. Send the header, ciphertext and tag to the server.  Store the document
       key in our own keyring, which is itself encrypted under vault_key.

  SHARE (Layla -> Omar)
    5. Fetch Omar's certificate; verify the CA's signature on it and that it
       names Omar.  This is where a lying server is caught.
    6. Build a manifest: manifest id, document id, "layla", "omar", the hash
       of the plaintext, the hash of the document's metadata header, and the
       current time.
    7. Sign the manifest with Layla's ECDSA key.  SIGN FIRST.
    8. ECDH between Layla's agreement key and Omar's; hash the result with
       both names and the document id into a key-wrapping key.
    9. Encrypt manifest + signature + document key under that key, with the
       share's routing header as associated data.  ENCRYPT SECOND.

  RETRIEVE (Omar)
   10. Decrypt the share.  A failure here means the share was tampered with,
       or was not meant for us.
   11. Verify Layla's signature over the manifest, against the signing key in
       her CA-issued certificate.
   12. Check the manifest names US as recipient, names the sender the routing
       header claims, is recent, and has an identifier we have never accepted
       before.  Record the identifier.
   13. Fetch the document.  Check its metadata header hashes to the value
       Layla signed.
   14. Decrypt with the document key; GCM verifies the ciphertext and the
       metadata together.
   15. Check the plaintext hashes to the value Layla signed.
   16. Only now hand the bytes to the caller.

  Nothing is returned to the caller before step 16.  Every check above
  raises, and they all raise the same opaque error.
"""

from __future__ import annotations

import os
import time

from . import ca as ca_module
from . import formats, params
from .crypto import ECDH, ECDSA, gcm, kdf, P256
from .crypto.blake2b import blake2b


class ClientError(Exception):
    """Anything that goes wrong, reported without detail.

    Section 7.6 asks what the client reports when verification fails and
    whether a detailed message assists an attacker.  It does: a client that
    distinguished "bad tag" from "bad signature" from "stale" would let an
    attacker probe which of its modifications the client noticed, and a
    server that could tell "wrong password" from "no such user" would leak
    the user list.  So callers get one error type and one message.  The
    reason is available for the user's own eyes through the `detail`
    attribute, which the CLI shows only for the local user's own actions and
    the demonstration uses to show WHICH check fired.
    """

    def __init__(self, message="operation failed", detail=None):
        super().__init__(message)
        self.detail = detail or message


class Receipt:


    def __init__(self, manifest_bytes, signature, certificate, plaintext,
                 origin):
        self.manifest_bytes = manifest_bytes
        self.signature = signature
        self.certificate = certificate
        self.plaintext = plaintext
        self.origin = origin
        # A document we uploaded ourselves has no manifest: there is nobody to
        # attest to us that we wrote our own file, and inventing a
        # self-signed one would be evidence of nothing.  `attested` is the
        # honest distinction, and the client shows it to the user: a document
        # is either "signed by <someone>" or "your own upload", never a vague
        # claim that covers both.
        self.manifest = (formats.decode_manifest(manifest_bytes)
                         if manifest_bytes else None)

    @property
    def attested(self) -> bool:
        return self.manifest is not None

    @property
    def sender(self):
        return self.manifest["sender"] if self.manifest else self.origin

    @property
    def recipient(self):
        return self.manifest["recipient"] if self.manifest else self.origin


def verify_receipt(receipt: Receipt, ca_public_key: P256.Point) -> dict:

    if not receipt.attested:
        raise ClientError(detail="this document carries no sender attestation")

    parsed = ca_module.verify_certificate(receipt.certificate, ca_public_key)
    manifest = formats.decode_manifest(receipt.manifest_bytes)

    if parsed["username"] != manifest["sender"]:
        raise ClientError(detail="certificate does not name the manifest sender")

    if not ECDSA.verify(parsed["signing_point"], receipt.manifest_bytes,
                        receipt.signature):
        raise ClientError(detail="signature does not verify")

    if blake2b(receipt.plaintext, digest_size=32) != manifest["plaintext_hash"]:
        raise ClientError(detail="document does not match the signed hash")

    return manifest


class Client:

    def __init__(self, server, ca_public_key: P256.Point, certificate_authority=None):
        self.server = server
        self.ca_public_key = ca_public_key
        self.certificate_authority = certificate_authority

        self.username = None
        self._session = None
        self._signing_private = None
        self._agreement_private = None
        self._vault_key = None
        self._certificate_cache = {}

    # =================================================================
    # Sign-up
    # =================================================================

    def register(self, username: str, password: str, profile=None) -> None:
        profile = profile or params.DEFAULT_PROFILE
        # Reject confusable names before anything is generated -- see the
        # note in params.py on the homograph attack this closes.
        if not params.is_valid_username(username):
            raise ClientError(detail="username must be lowercase ASCII "
                                     "letters, digits, _ or -")
        if self.certificate_authority is None:
            raise ClientError(detail="no certificate authority configured")

        # A fresh salt per user.  Not secret -- its job is to make each user a
        # separate problem, so that one precomputed table cannot attack the
        # whole database and two users with the same password do not produce
        # the same record.
        salt = os.urandom(params.SALT_SIZE)

        master = kdf.derive_master_key(password, salt, profile)
        auth_token = kdf.derive_auth_token(master)
        vault_key = kdf.derive_vault_key(master)

        signing_private, signing_public = P256.generate_keypair()
        agreement_private, agreement_public = P256.generate_keypair()

        certificate = self.certificate_authority.issue(
            username,
            P256.encode_point(signing_public),
            P256.encode_point(agreement_public),
        )

        credential = formats.encode_credential(
            username=username, salt=salt, profile=profile,
            verifier=kdf.derive_verifier(auth_token),
            created_at=int(time.time()),
        )

        keystore = self._wrap_keystore(username, vault_key, signing_private,
                                       agreement_private)

        self.server.register(username, credential, keystore, certificate)

        # An empty keyring, so that the object exists from the first moment
        # and login never has to special-case its absence.
        self._username_for_wrap = username
        self._vault_key = vault_key
        self._session = self.server.login(username, auth_token)
        self.username = username
        self._signing_private = signing_private
        self._agreement_private = agreement_private
        self._save_keyring({}, set())

    # =================================================================
    # Login
    # =================================================================

    def login(self, username: str, password: str) -> None:
        challenge = self.server.login_challenge(username)

        # we compute Argon2id before knowing whether the account exists.
        # That is deliberate -- the server answers this challenge for every
        # username, so an attacker learns nothing from the timing of it.
        profile = params.Argon2Profile(
            "recorded", challenge["memory_cost"], challenge["time_cost"],
            challenge["parallelism"])
        master = kdf.derive_master_key(password, challenge["salt"], profile)
        auth_token = kdf.derive_auth_token(master)

        try:
            self._session = self.server.login(username, auth_token)
        except Exception:
            raise ClientError(detail="login failed")

        self.username = username
        self._vault_key = kdf.derive_vault_key(master)

        keystore = self.server.get_keystore(self._session)
        self._signing_private, self._agreement_private = self._unwrap_keystore(
            username, self._vault_key, keystore)

    def logout(self) -> None:
        if self._session:
            self.server.logout(self._session)
        self.username = None
        self._session = None
        self._signing_private = None
        self._agreement_private = None
        self._vault_key = None

    def _require_login(self):
        if self._session is None:
            raise ClientError(detail="not logged in")

    # =================================================================
    # Key material at rest
    # =================================================================

    def _wrap_keystore(self, username, vault_key, signing_private,
                       agreement_private) -> bytes:
        nonce = os.urandom(params.GCM_NONCE_SIZE)
        plaintext = (P256.encode_scalar(signing_private)
                     + P256.encode_scalar(agreement_private))
        _, header = formats.encode_keystore(username, nonce, b"", b"\x00" * 16)
        ciphertext, tag = gcm.encrypt(vault_key, nonce, plaintext, header)
        blob, _ = formats.encode_keystore(username, nonce, ciphertext, tag)
        return blob

    def _unwrap_keystore(self, username, vault_key, keystore: bytes):
        try:
            parsed = formats.decode_keystore(keystore)
            if parsed["username"] != username:
                raise ClientError(detail="keystore names the wrong user")
            plaintext = gcm.decrypt(vault_key, parsed["nonce"],
                                    parsed["ciphertext"], parsed["tag"],
                                    parsed["header"])
        except (formats.FormatError, gcm.AuthenticationError):
            raise ClientError(detail="keystore could not be opened")

        if len(plaintext) != 64:
            raise ClientError(detail="keystore is malformed")
        return (P256.decode_scalar(plaintext[:32]),
                P256.decode_scalar(plaintext[32:]))

    def _load_keyring(self):
        blob = self.server.get_keyring(self._session)
        if blob is None:
            return {}, set()
        try:
            parsed = formats.decode_keyring(blob)
            if parsed["username"] != self.username:
                raise ClientError(detail="keyring names the wrong user")
            plaintext = gcm.decrypt(self._vault_key, parsed["nonce"],
                                    parsed["ciphertext"], parsed["tag"],
                                    parsed["header"])
            return formats.decode_keyring_contents(plaintext)
        except (formats.FormatError, gcm.AuthenticationError):
            raise ClientError(detail="keyring could not be opened")

    def _save_keyring(self, entries, seen):
        nonce = os.urandom(params.GCM_NONCE_SIZE)
        header = formats.encode_keyring_header(self.username, nonce)
        plaintext = formats.encode_keyring_contents(entries, seen)
        ciphertext, tag = gcm.encrypt(self._vault_key, nonce, plaintext, header)
        self.server.put_keyring(self._session,
                                formats.encode_keyring(header, ciphertext, tag))

    # =================================================================
    # Certificates -- the only place a public key enters the system
    # =================================================================

    def certificate_for(self, username: str) -> dict:
        """Fetch and verify another user's certificate.

        Every guarantee in the system depends on this function being
        paranoid.  The server hands us bytes; we believe them only because
        the CA signed them, the CA's public key reached us out of band, and
        the name inside the signature is the name we asked for.
        """
        if username in self._certificate_cache:
            return self._certificate_cache[username]

        try:
            raw = self.server.get_certificate(username)
        except Exception:
            raise ClientError(detail=f"no certificate for {username}")

        try:
            parsed = ca_module.verify_certificate(
                raw, self.ca_public_key, expected_username=username)
        except ca_module.CertificateError:
            raise ClientError(detail="certificate rejected")

        parsed["raw"] = raw
        self._certificate_cache[username] = parsed
        return parsed

    def fingerprint_of(self, username: str) -> str:
        """The value two users compare out of band.

        The certificate chain already binds this key to this name, so this is
        a second, independent layer -- it is what a cautious pair of users can
        do if they do not want to rely on the CA alone.
        """
        parsed = self.certificate_for(username)
        return kdf.format_fingerprint(parsed["signing_key"])

    # =================================================================
    # Upload
    # =================================================================

    def upload(self, filename: str, plaintext: bytes,
               mimetype: str = "application/octet-stream") -> bytes:
        self._require_login()

        # A fresh key per document.  This single rule is what removes GCM's
        # nonce-reuse failure mode entirely: a key that encrypts exactly one
        # message cannot repeat a (key, nonce) pair, whatever happens to the
        # process afterwards.  There is no counter to persist across a crash
        # and therefore no counter to lose.
        document_key = os.urandom(params.SYMMETRIC_KEY_SIZE)
        nonce = os.urandom(params.GCM_NONCE_SIZE)
        doc_id = os.urandom(16)

        header = formats.encode_document_header(
            doc_id=doc_id, owner=self.username, filename=filename,
            mimetype=mimetype, size=len(plaintext),
            uploaded_at=int(time.time()), nonce=nonce)

        # The entire metadata header is the associated data.  This is the
        # metadata-binding mechanism: the server can read the file name, and
        # cannot change it.
        ciphertext, tag = gcm.encrypt(document_key, nonce, plaintext, header)
        document = formats.encode_document(header, ciphertext, tag)

        self.server.put_document(self._session, document)

        entries, seen = self._load_keyring()
        entries[doc_id] = {"document_key": document_key,
                           "origin": self.username,
                           "manifest": b"", "signature": b"\x00" * 64}
        self._save_keyring(entries, seen)
        return doc_id

    # =================================================================
    # Share
    # =================================================================

    def share(self, doc_id: bytes, recipient: str) -> bytes:
        self._require_login()

        entries, seen = self._load_keyring()
        if doc_id not in entries:
            raise ClientError(detail="no key for that document")
        document_key = entries[doc_id]["document_key"]

        recipient_certificate = self.certificate_for(recipient)

        document = formats.decode_document(
            self.server.get_document(self._session, doc_id))
        plaintext = gcm.decrypt(document_key, document["nonce"],
                                document["ciphertext"], document["tag"],
                                document["header"])

        manifest = formats.encode_manifest(
            manifest_id=os.urandom(16),
            doc_id=doc_id,
            sender=self.username,
            recipient=recipient,
            plaintext_hash=blake2b(plaintext, digest_size=32),
            metadata_hash=blake2b(document["header"], digest_size=32),
            created_at=int(time.time()),
        )

        # SIGN FIRST.  The signature covers the recipient's name, which is
        # what stops the recipient re-sending this same signed statement to
        # somebody else and passing it off as addressed to them.
        signature = ECDSA.sign(self._signing_private, manifest)

        # THEN ENCRYPT.  The key comes from ECDH with the recipient, bound by
        # the hkdf to both names and this document.
        shared = ECDH.shared_secret(self._agreement_private,
                                    recipient_certificate["agreement_point"])
        wrapping_key = kdf.derive_kek(shared, self.username, recipient, doc_id)

        share_id = os.urandom(16)
        nonce = os.urandom(params.GCM_NONCE_SIZE)
        header = formats.encode_share_header(share_id, doc_id, self.username,
                                             recipient, nonce)
        sealed = formats.encode_sealed_payload(manifest, signature,
                                               document_key)
        ciphertext, tag = gcm.encrypt(wrapping_key, nonce, sealed, header)

        self.server.put_share(self._session,
                              formats.encode_share(header, ciphertext, tag))
        return share_id

    # =================================================================
    # Accepting shares
    # =================================================================

    def accept_shares(self, now: int = None) -> list:
        """Process every share addressed to us that we have not yet accepted.

        Returns a list of (doc_id, sender) for the ones newly accepted.
        Shares that fail any check are skipped, not raised on, so one bad
        object cannot block the rest of the inbox -- but the reason is
        recorded so the demonstration can show which check fired.
        """
        self._require_login()
        now = int(time.time()) if now is None else now

        entries, seen = self._load_keyring()
        accepted = []
        self.last_rejections = []

        for raw in self.server.list_shares(self._session):
            try:
                doc_id, sender, manifest_id, manifest, signature = \
                    self._open_share(raw, seen, now)
            except ClientError as error:
                self.last_rejections.append(error.detail)
                continue

            seen.add(manifest_id)
            entries[doc_id] = {"document_key": self._pending_document_key,
                               "origin": sender,
                               "manifest": manifest,
                               "signature": signature}
            accepted.append((doc_id, sender))

        if accepted:
            self._save_keyring(entries, seen)
        return accepted

    def _open_share(self, raw: bytes, seen: set, now: int):
        try:
            share = formats.decode_share(raw)
        except formats.FormatError:
            raise ClientError(detail="share is malformed")

        if share["recipient"] != self.username:
            raise ClientError(detail="share is addressed to someone else")

        sender_certificate = self.certificate_for(share["sender"])

        shared = ECDH.shared_secret(self._agreement_private,
                                    sender_certificate["agreement_point"])
        wrapping_key = kdf.derive_kek(shared, share["sender"],
                                      share["recipient"], share["doc_id"])

        try:
            sealed = gcm.decrypt(wrapping_key, share["nonce"], share["sealed"],
                                 share["tag"], share["header"])
            payload = formats.decode_sealed_payload(sealed)
        except (gcm.AuthenticationError, formats.FormatError):
            raise ClientError(detail="share failed authentication")

        # -- the signature, before anything inside is believed -------------
        if not ECDSA.verify(sender_certificate["signing_point"],
                            payload["manifest"], payload["signature"]):
            raise ClientError(detail="manifest signature does not verify")

        try:
            manifest = formats.decode_manifest(payload["manifest"])
        except formats.FormatError:
            raise ClientError(detail="manifest is malformed")

        # -- the signed fields must agree with the routing header -----------
        # The header is what the server can rewrite; the manifest is what the
        # sender signed.  Where they disagree, the manifest wins and the
        # object is refused.
        if manifest["sender"] != share["sender"]:
            raise ClientError(detail="sender in manifest does not match header")
        if manifest["doc_id"] != share["doc_id"]:
            raise ClientError(detail="document id does not match header")

        # -- surreptitious forwarding ---------------------------------------
        if manifest["recipient"] != self.username:
            raise ClientError(detail="manifest is addressed to someone else")

        # -- freshness -------------------------------------------------------
        # Two mechanisms, and both are needed.  The time window bounds how long
        # a captured object stays useful and therefore how large the accepted
        # list has to grow.  The accepted list is what actually stops a replay
        # INSIDE the window, which a timestamp alone cannot do.
        age = now - manifest["created_at"]
        if age > params.FRESHNESS_WINDOW_SECONDS:
            raise ClientError(detail="share is stale")
        if age < -params.FRESHNESS_WINDOW_SECONDS:
            raise ClientError(detail="share is dated in the future")
        if manifest["manifest_id"] in seen:
            raise ClientError(detail="share has already been accepted (replay)")

        self._pending_document_key = payload["document_key"]
        return (manifest["doc_id"], manifest["sender"],
                manifest["manifest_id"], payload["manifest"],
                payload["signature"])

    # =================================================================
    # Retrieve
    # =================================================================

    def retrieve(self, doc_id: bytes) -> Receipt:
        """Fetch, verify and decrypt a document.  Nothing is returned unless
        every check passes."""
        self._require_login()

        entries, _ = self._load_keyring()
        if doc_id not in entries:
            raise ClientError(detail="no key for that document")
        entry = entries[doc_id]

        try:
            document = formats.decode_document(
                self.server.get_document(self._session, doc_id))
        except formats.FormatError:
            raise ClientError(detail="document is malformed")

        if document["doc_id"] != doc_id:
            raise ClientError(detail="server returned the wrong document")

        # If the document came from someone else, the manifest they signed
        # commits to the metadata header.  Check that BEFORE decrypting, so a
        # substituted header is caught by the signature rather than only by
        # the GCM tag.
        manifest = None
        if entry["manifest"]:
            manifest = formats.decode_manifest(entry["manifest"])
            if blake2b(document["header"], digest_size=32) != manifest["metadata_hash"]:
                raise ClientError(detail="metadata does not match the signed hash")

        try:
            plaintext = gcm.decrypt(entry["document_key"], document["nonce"],
                                    document["ciphertext"], document["tag"],
                                    document["header"])
        except gcm.AuthenticationError:
            raise ClientError(detail="document failed authentication")

        if len(plaintext) != document["size"]:
            raise ClientError(detail="document length does not match metadata")

        certificate = None
        if manifest is not None:
            if blake2b(plaintext, digest_size=32) != manifest["plaintext_hash"]:
                raise ClientError(detail="document does not match the signed hash")
            certificate = self.certificate_for(manifest["sender"])["raw"]

        return Receipt(entry["manifest"], entry["signature"], certificate,
                       plaintext, entry["origin"])

    # =================================================================
    # Listing and password change
    # =================================================================

    def list_documents(self) -> list:
        self._require_login()
        entries, _ = self._load_keyring()
        listing = []
        for record in self.server.list_documents(self._session):
            record = dict(record)
            record["have_key"] = record["doc_id"] in entries
            record["origin"] = entries.get(record["doc_id"], {}).get("origin")
            listing.append(record)
        return listing

    def change_password(self, old_password: str, new_password: str,
                        profile=None) -> None:

        self._require_login()
        profile = profile or params.DEFAULT_PROFILE

        entries, seen = self._load_keyring()

        salt = os.urandom(params.SALT_SIZE)
        master = kdf.derive_master_key(new_password, salt, profile)
        auth_token = kdf.derive_auth_token(master)
        self._vault_key = kdf.derive_vault_key(master)

        self.server.put_keystore(
            self._session,
            self._wrap_keystore(self.username, self._vault_key,
                                self._signing_private, self._agreement_private))
        self._save_keyring(entries, seen)
        self.server.put_credential(
            self._session,
            formats.encode_credential(
                username=self.username, salt=salt, profile=profile,
                verifier=kdf.derive_verifier(auth_token),
                created_at=int(time.time())))
