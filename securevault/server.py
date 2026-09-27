"""The SecureVault server -- honest-but-curious, and structurally blind.

WHAT THE SERVER DOES

  * stores credential records, wrapped keystores, certificates, encrypted
    documents and share records
  * checks a login proof and issues a session
  * routes share records from sender to recipient
  * enforces access control on document retrieval
"""

from __future__ import annotations

import os
import time

from . import ca as ca_module
from . import formats, params
from .crypto.blake2b import blake2b
from .crypto.gcm import constant_time_equals
from .crypto import P256
from .storage import Storage

SESSION_LIFETIME_SECONDS = 3600


class ServerError(Exception):
    """Every server-side refusal, with a deliberately uninformative message."""


class Server:
    def __init__(self, root: str, ca_public_key: P256.Point):
        self.storage = Storage(root)
        self.ca_public_key = ca_public_key
        self._fake_salt_secret = self._load_or_create_fake_salt_secret()

    # ------------------------------------------------------------------
    # Making a failed login indistinguishable from an unknown user
    # ------------------------------------------------------------------
    #
    # Requirement 5.2 says a failed login must not reveal whether the account
    # exists, "not through its message, and not through how long it takes".
    #
    # That is harder than it looks in our design, because Argon2id runs on the
    # CLIENT.  To attempt a login the client must first ask the server for the
    # user's salt and work factor.  A server that answered "no such user"
    # would leak existence immediately, and one that answered with a random
    # salt would leak it too -- ask twice, get two different salts, and you
    # know the account is not real.
    #
    # So unknown users get a salt that is DETERMINISTIC in the username, keyed
    # by a server-side secret.  It is stable across queries, indistinguishable
    # from a real salt, and unpredictable without the secret.  The client then
    # spends exactly as long computing Argon2id as it would for a real
    # account, sends a token, and is refused by the same code path with the
    # same message.

    def _load_or_create_fake_salt_secret(self) -> bytes:
        secret = self.storage.get("config", "fake-salt-secret")
        if secret is None:
            secret = os.urandom(32)
            self.storage.put("config", "fake-salt-secret", secret)
        return secret

    def _fake_salt(self, username: str) -> bytes:
        return blake2b(username.encode("utf-8"), key=self._fake_salt_secret,
                       digest_size=params.SALT_SIZE, person=b"SV-FAKESALT")

    def _fake_verifier(self, username: str) -> bytes:
        return blake2b(username.encode("utf-8"), key=self._fake_salt_secret,
                       digest_size=32, person=b"SV-FAKEVERIF")

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, username: str, credential_record: bytes,
                 keystore: bytes, certificate: bytes) -> None:
        if not params.is_valid_username(username):
            raise ServerError("registration refused")
        if self.storage.exists("credentials", username):
            raise ServerError("registration refused")

        # Check the certificate before storing it.  The server cannot forge
        # one, but it can refuse to store rubbish, and doing so means every
        # certificate it later hands out has already been checked once.  Note
        # the username binding: this is what stops Mallory registering under
        # the name "layla" with a certificate issued to "mallory".
        try:
            ca_module.verify_certificate(certificate, self.ca_public_key,
                                         expected_username=username)
        except ca_module.CertificateError:
            raise ServerError("registration refused")

        # Sanity-check the other two objects parse and name the right user.
        try:
            credential = formats.decode_credential(credential_record)
            parsed_keystore = formats.decode_keystore(keystore)
        except formats.FormatError:
            raise ServerError("registration refused")
        if (credential["username"] != username
                or parsed_keystore["username"] != username):
            raise ServerError("registration refused")

        self.storage.put("credentials", username, credential_record)
        self.storage.put("keystores", username, keystore)
        self.storage.put("certificates", username, certificate)

    # ------------------------------------------------------------------
    # Login
    # ------------------------------------------------------------------

    def login_challenge(self, username: str) -> dict:
        """Return the salt and work factor the client needs.

        Answers for every username, real or not -- see the note above.
        """
        stored = self.storage.get("credentials", username)
        if stored is None:
            profile = params.DEFAULT_PROFILE
            return {"salt": self._fake_salt(username),
                    "memory_cost": profile.memory_cost,
                    "time_cost": profile.time_cost,
                    "parallelism": profile.parallelism}

        credential = formats.decode_credential(stored)
        return {"salt": credential["salt"],
                "memory_cost": credential["memory_cost"],
                "time_cost": credential["time_cost"],
                "parallelism": credential["parallelism"]}

    def login(self, username: str, auth_token: bytes) -> bytes:
        """Verify the proof and return a session token.

        Both branches do the same work: one BLAKE2b of the presented token,
        one constant-time comparison against 32 bytes.  For an unknown user
        the 32 bytes are a deterministic fake rather than a real verifier, so
        the comparison happens either way and fails either way.
        """
        stored = self.storage.get("credentials", username)
        if stored is None:
            expected = self._fake_verifier(username)
        else:
            expected = formats.decode_credential(stored)["verifier"]

        presented = blake2b(b"", key=auth_token, digest_size=32,
                            person=params.LABEL_VERIFIER)

        if not constant_time_equals(presented, expected):
            raise ServerError("login failed")

        return self._create_session(username)

    def _create_session(self, username: str) -> bytes:
        token = os.urandom(32)
        # The session table stores a HASH of the token, not the token.  A
        # stolen database then yields no usable sessions -- the same reasoning
        # as for passwords, applied to a value that is already high-entropy,
        # so a fast hash suffices.
        record = (username.encode("utf-8") + b"\x00"
                  + str(int(time.time()) + SESSION_LIFETIME_SECONDS).encode())
        self.storage.put("sessions", blake2b(token, digest_size=32), record)
        return token

    def _username_for_session(self, token: bytes) -> str:
        record = self.storage.get("sessions", blake2b(token, digest_size=32))
        if record is None:
            raise ServerError("not authorised")
        username, _, expiry = record.partition(b"\x00")
        if int(expiry) < int(time.time()):
            raise ServerError("not authorised")
        return username.decode("utf-8")

    def logout(self, token: bytes) -> None:
        self.storage.delete("sessions", blake2b(token, digest_size=32))

    # ------------------------------------------------------------------
    # Key distribution
    # ------------------------------------------------------------------

    def get_certificate(self, username: str) -> bytes:
        """Hand out a user's certificate.

        Note what is NOT promised here: the server is not trusted to return
        the right one.  The client verifies the CA signature and the username
        binding itself.  This call is a lookup, not an assertion.
        """
        certificate = self.storage.get("certificates", username)
        if certificate is None:
            raise ServerError("no such certificate")
        return certificate

    def get_keystore(self, session: bytes) -> bytes:
        username = self._username_for_session(session)
        keystore = self.storage.get("keystores", username)
        if keystore is None:
            raise ServerError("not authorised")
        return keystore

    def put_keystore(self, session: bytes, keystore: bytes) -> None:
        """Used by a password change: the wrapper changes, the keys do not."""
        username = self._username_for_session(session)
        parsed = formats.decode_keystore(keystore)
        if parsed["username"] != username:
            raise ServerError("not authorised")
        self.storage.put("keystores", username, keystore)

    def get_keyring(self, session: bytes) -> bytes:
        """The user's wrapped document keys.  Opaque to us, like the keystore."""
        username = self._username_for_session(session)
        return self.storage.get("keyrings", username)

    def put_keyring(self, session: bytes, keyring: bytes) -> None:
        username = self._username_for_session(session)
        try:
            parsed = formats.decode_keyring(keyring)
        except formats.FormatError:
            raise ServerError("refused")
        if parsed["username"] != username:
            raise ServerError("not authorised")
        self.storage.put("keyrings", username, keyring)

    def put_credential(self, session: bytes, credential_record: bytes) -> None:
        username = self._username_for_session(session)
        credential = formats.decode_credential(credential_record)
        if credential["username"] != username:
            raise ServerError("not authorised")
        self.storage.put("credentials", username, credential_record)

    # ------------------------------------------------------------------
    # Documents
    # ------------------------------------------------------------------

    def put_document(self, session: bytes, document: bytes) -> bytes:
        username = self._username_for_session(session)
        try:
            parsed = formats.decode_document(document)
        except formats.FormatError:
            raise ServerError("upload refused")
        if parsed["owner"] != username:
            raise ServerError("upload refused")
        if self.storage.exists("documents", parsed["doc_id"]):
            raise ServerError("upload refused")

        self.storage.put("documents", parsed["doc_id"], document)
        self._grant(parsed["doc_id"], username)
        return parsed["doc_id"]

    def get_document(self, session: bytes, doc_id: bytes) -> bytes:
        username = self._username_for_session(session)
        if username not in self._readers(doc_id):
            raise ServerError("not authorised")
        document = self.storage.get("documents", doc_id)
        if document is None:
            raise ServerError("not authorised")
        return document

    def list_documents(self, session: bytes) -> list:
        """Metadata the server legitimately holds, for the user's own view."""
        username = self._username_for_session(session)
        listing = []
        for doc_id in self.storage.list_keys("documents"):
            if username not in self._readers(doc_id):
                continue
            parsed = formats.decode_document(
                self.storage.get("documents", doc_id))
            listing.append({k: parsed[k] for k in
                            ("doc_id", "owner", "filename", "mimetype",
                             "size", "uploaded_at")})
        return listing

    # -- access control list --------------------------------------------
    #
    # Defence in depth only.  The server cannot read documents in any case, so
    # this list is not what keeps them confidential -- the encryption is.  It
    # is here because an honest-but-curious server following the protocol
    # should not hand ciphertext to people with no business holding it, and
    # because withholding it limits what a passive collector accumulates.

    def _readers(self, doc_id: bytes) -> set:
        record = self.storage.get("acl", doc_id)
        if record is None:
            return set()
        return set(record.decode("utf-8").split("\x00"))

    def _grant(self, doc_id: bytes, username: str) -> None:
        readers = self._readers(doc_id)
        readers.add(username)
        self.storage.put("acl", doc_id,
                         "\x00".join(sorted(readers)).encode("utf-8"))

    # ------------------------------------------------------------------
    # Sharing
    # ------------------------------------------------------------------

    def put_share(self, session: bytes, share: bytes) -> None:
        username = self._username_for_session(session)
        try:
            parsed = formats.decode_share(share)
        except formats.FormatError:
            raise ServerError("share refused")

        # The server checks only what it is entitled to check: that the
        # claimed sender is the logged-in user, and that the document exists
        # and is theirs to share.  It cannot check the signature inside --
        # that is encrypted, and checking it is the recipient's job.
        if parsed["sender"] != username:
            raise ServerError("share refused")
        if username not in self._readers(parsed["doc_id"]):
            raise ServerError("share refused")
        if not self.storage.exists("credentials", parsed["recipient"]):
            raise ServerError("share refused")

        self.storage.put("shares",
                         parsed["recipient"].encode("utf-8") + b"/"
                         + parsed["share_id"], share)
        self._grant(parsed["doc_id"], parsed["recipient"])

    def list_shares(self, session: bytes) -> list:
        username = self._username_for_session(session)
        prefix = username.encode("utf-8") + b"/"
        return [self.storage.get("shares", key)
                for key in self.storage.list_keys("shares")
                if key.startswith(prefix)]

    # ------------------------------------------------------------------
    # Inspection helpers for the live demonstration
    # ------------------------------------------------------------------

    def raw_path(self, collection: str, key) -> str:
        return self.storage.path_of(collection, key)

    def raw_object(self, collection: str, key) -> bytes:
        return self.storage.get(collection, key)
