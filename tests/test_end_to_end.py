"""End-to-end tests: the Section 2 scenario, and every way of breaking it.

The first test is the story from the specification -- Layla registers,
uploads, shares with Omar; Omar downloads, opens it, and learns who sent it.
Everything after that is an attacker trying to break that story, and each of
those tests corresponds to a numbered line of the Section 8 demonstration.
"""

import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from securevault import formats, params
from securevault.ca import CertificateAuthority
from securevault.client import Client, ClientError, Receipt, verify_receipt
from securevault.crypto import P256
from securevault.server import Server, ServerError

THESIS = b"A thesis draft nobody but Omar may read.\n" * 40


@pytest.fixture
def world(tmp_path):
    """A certificate authority, a server, and two users on separate machines."""
    authority = CertificateAuthority(str(tmp_path / "ca"))
    ca_public = P256.decode_point(authority.export_trust_anchor())
    server = Server(str(tmp_path / "server"), ca_public)

    # Two Client objects with independent state: the "separate machines or
    # separate directories" of demonstration requirement 1.
    layla = Client(server, ca_public, authority)
    omar = Client(server, ca_public, authority)

    layla.register("layla", "layla-correct-horse-battery", params.DEMO)
    omar.register("omar", "omar-a-different-long-password", params.DEMO)

    return {"ca": authority, "ca_public": ca_public, "server": server,
            "layla": layla, "omar": omar, "root": tmp_path}


# =====================================================================
# The honest path
# =====================================================================

def test_the_specification_scenario(world):
    layla, omar, server = world["layla"], world["omar"], world["server"]

    doc_id = layla.upload("thesis-draft.pdf", THESIS, "application/pdf")
    layla.share(doc_id, "omar")

    accepted = omar.accept_shares()
    assert accepted == [(doc_id, "layla")]

    receipt = omar.retrieve(doc_id)
    assert receipt.plaintext == THESIS
    assert receipt.sender == "layla"           # "it came from Layla"
    assert receipt.recipient == "omar"

    # "He can show a third party that it came from Layla."  The third party
    # holds only the CA's public key.
    manifest = verify_receipt(receipt, world["ca_public"])
    assert manifest["sender"] == "layla"


def test_owner_can_retrieve_their_own_document(world):
    layla = world["layla"]
    doc_id = layla.upload("notes.txt", b"my own notes")
    assert layla.retrieve(doc_id).plaintext == b"my own notes"


def test_login_from_a_fresh_client_with_only_the_password(world):
    """Section 7.3: what recovers the private material when the user has only
    their password?  Nothing is kept on this machine -- a brand new Client
    object logs in and reads a document shared earlier."""
    layla, omar, server = world["layla"], world["omar"], world["server"]
    doc_id = layla.upload("report.txt", b"quarterly numbers")
    layla.share(doc_id, "omar")
    omar.accept_shares()

    somewhere_else = Client(server, world["ca_public"])
    somewhere_else.login("omar", "omar-a-different-long-password")
    assert somewhere_else.retrieve(doc_id).plaintext == b"quarterly numbers"


# =====================================================================
# Demonstration requirement 2: the stored credential record
# =====================================================================

def test_credential_record_reveals_nothing_about_the_password(world):
    server = world["server"]
    record = server.raw_object("credentials", "layla")
    parsed = formats.decode_credential(record)

    password = b"layla-correct-horse-battery"
    assert password not in record
    assert b"layla-correct" not in record
    # The only password-derived value present is the verifier, and it is the
    # output of BLAKE2b over an Argon2id output.
    assert len(parsed["verifier"]) == 32
    assert parsed["salt"] != b"\x00" * 16

    # Two users with the same password must not look alike.
    other = Client(server, world["ca_public"], world["ca"])
    other.register("twin", "layla-correct-horse-battery", params.DEMO)
    twin = formats.decode_credential(server.raw_object("credentials", "twin"))
    assert twin["verifier"] != parsed["verifier"]
    assert twin["salt"] != parsed["salt"]


# =====================================================================
# Demonstration requirement 3: the server's stored copy is unreadable
# =====================================================================

def test_server_storage_contains_no_plaintext(world):
    layla = world["layla"]
    doc_id = layla.upload("thesis-draft.pdf", THESIS, "application/pdf")
    stored = world["server"].raw_object("documents", doc_id)

    assert THESIS not in stored
    assert b"A thesis draft" not in stored
    # The metadata the server legitimately needs IS present, in the clear.
    assert b"thesis-draft.pdf" in stored


def test_server_cannot_read_the_keystore_or_keyring(world):
    server = world["server"]
    layla = world["layla"]
    layla.upload("secret.txt", b"contents")

    for collection in ("keystores", "keyrings"):
        blob = server.raw_object(collection, "layla")
        assert blob is not None
        assert b"contents" not in blob


# =====================================================================
# Demonstration requirement 6: a single byte of ciphertext is altered
# =====================================================================

def test_flipping_one_byte_of_ciphertext_is_rejected(world):
    layla, omar, server = world["layla"], world["omar"], world["server"]
    doc_id = layla.upload("thesis.pdf", THESIS)
    layla.share(doc_id, "omar")
    omar.accept_shares()

    stored = bytearray(server.raw_object("documents", doc_id))
    parsed = formats.decode_document(bytes(stored))
    offset = len(parsed["header"]) + 4          # first byte of ciphertext
    stored[offset] ^= 0x01
    server.storage.put("documents", doc_id, bytes(stored))

    with pytest.raises(ClientError) as error:
        omar.retrieve(doc_id)
    assert "authentication" in error.value.detail


# =====================================================================
# Demonstration requirement 7: a metadata field is altered
# =====================================================================

def test_altering_the_file_name_is_rejected(world):
    """The metadata is not encrypted -- the server can read it.  It is the
    AAD of the GCM encryption, so the server cannot change it."""
    layla, omar, server = world["layla"], world["omar"], world["server"]
    doc_id = layla.upload("thesis.pdf", THESIS)
    layla.share(doc_id, "omar")
    omar.accept_shares()

    stored = server.raw_object("documents", doc_id)
    tampered = stored.replace(b"thesis.pdf", b"thesis.exe")
    assert tampered != stored
    server.storage.put("documents", doc_id, tampered)

    with pytest.raises(ClientError):
        omar.retrieve(doc_id)


def test_altering_the_recorded_size_is_rejected(world):
    layla, omar, server = world["layla"], world["omar"], world["server"]
    doc_id = layla.upload("thesis.pdf", THESIS)
    layla.share(doc_id, "omar")
    omar.accept_shares()

    stored = bytearray(server.raw_object("documents", doc_id))
    parsed = formats.decode_document(bytes(stored))
    size_offset = parsed["header"].index(parsed["size"].to_bytes(8, "big"))
    stored[size_offset:size_offset + 8] = (parsed["size"] + 1).to_bytes(8, "big")
    server.storage.put("documents", doc_id, bytes(stored))

    with pytest.raises(ClientError):
        omar.retrieve(doc_id)


def test_altering_the_owner_is_rejected(world):
    layla, omar, server = world["layla"], world["omar"], world["server"]
    doc_id = layla.upload("thesis.pdf", THESIS)
    layla.share(doc_id, "omar")
    omar.accept_shares()

    stored = server.raw_object("documents", doc_id)
    server.storage.put("documents", doc_id,
                       stored.replace(b"\x05layla", b"\x05mally"))
    with pytest.raises(ClientError):
        omar.retrieve(doc_id)


# =====================================================================
# Demonstration requirement 8: replay
# =====================================================================

def test_replaying_an_accepted_share_is_rejected(world):
    """Within the freshness window, so the timestamp alone would not catch
    it.  The accepted-manifest list is what refuses it."""
    layla, omar, server = world["layla"], world["omar"], world["server"]
    doc_id = layla.upload("thesis.pdf", THESIS)
    layla.share(doc_id, "omar")

    captured = server.list_shares(omar._session)[0]
    assert omar.accept_shares() == [(doc_id, "layla")]

    # The attacker puts the very same object back and the client sees it again.
    parsed = formats.decode_share(captured)
    server.storage.put("shares", b"omar/" + os.urandom(16), captured)

    assert omar.accept_shares() == []
    assert any("replay" in reason for reason in omar.last_rejections)


def test_a_share_captured_yesterday_is_stale(world):
    layla, omar, server = world["layla"], world["omar"], world["server"]
    doc_id = layla.upload("thesis.pdf", THESIS)
    layla.share(doc_id, "omar")

    # Deliver it a day later.
    tomorrow = int(time.time()) + 24 * 3600
    assert omar.accept_shares(now=tomorrow) == []
    assert any("stale" in reason for reason in omar.last_rejections)


def test_a_future_dated_share_is_rejected(world):
    layla, omar = world["layla"], world["omar"]
    doc_id = layla.upload("thesis.pdf", THESIS)
    layla.share(doc_id, "omar")

    yesterday = int(time.time()) - 24 * 3600
    assert omar.accept_shares(now=yesterday) == []
    assert any("future" in reason for reason in omar.last_rejections)


# =====================================================================
# Attacks on identity and routing
# =====================================================================

def test_mallory_cannot_read_a_share_meant_for_omar(world):
    layla, server = world["layla"], world["server"]
    mallory = Client(server, world["ca_public"], world["ca"])
    mallory.register("mallory", "mallory-a-long-password", params.DEMO)

    doc_id = layla.upload("thesis.pdf", THESIS)
    layla.share(doc_id, "omar")

    captured = server.list_shares(world["omar"]._session)[0]
    server.storage.put("shares", b"mallory/" + os.urandom(16), captured)

    assert mallory.accept_shares() == []
    assert mallory.last_rejections


def _hand_craft_share(sender_client, sender_name, recipient_name,
                      doc_id, manifest, signature, document_key, server):
    """Build and post a share record directly, bypassing Client.share().

    The attack tests need to construct objects an honest client would never
    produce, so they assemble them here rather than going through the API.
    """
    from securevault.crypto import ECDH, gcm, kdf
    recipient_certificate = sender_client.certificate_for(recipient_name)
    shared = ECDH.shared_secret(sender_client._agreement_private,
                                recipient_certificate["agreement_point"])
    wrapping = kdf.derive_kek(shared, sender_name, recipient_name, doc_id)
    share_id = os.urandom(16)
    nonce = os.urandom(12)
    header = formats.encode_share_header(share_id, doc_id, sender_name,
                                         recipient_name, nonce)
    sealed = formats.encode_sealed_payload(manifest, signature, document_key)
    ciphertext, tag = gcm.encrypt(wrapping, nonce, sealed, header)
    server.storage.put("shares", recipient_name.encode() + b"/" + share_id,
                       formats.encode_share(header, ciphertext, tag))


def test_omar_cannot_re_wrap_laylas_manifest_as_his_own(world):
    """Omar takes Layla's signed manifest and re-sends it to Mallory.

    He cannot claim to BE Layla -- the wrapping key is derived from an ECDH
    secret with Layla's private key, which he does not have -- so the best he
    can do is send it under his own name.

    Note WHICH check fires, because it is not the one you might expect.
    Mallory's client verifies the manifest signature against the certificate
    of whoever the ROUTING HEADER names, which here is Omar.  Layla's
    signature does not verify under Omar's key, so the object is refused at
    the signature step, before the explicit sender-mismatch comparison is
    ever reached.  That comparison is still there as a second line -- it
    catches the case where the two names differ but the signature somehow
    checked out -- but in this attack the signature check gets there first.
    We assert the reason we actually observe rather than the one we assumed.
    """
    layla, omar, server = world["layla"], world["omar"], world["server"]
    mallory = Client(server, world["ca_public"], world["ca"])
    mallory.register("mallory", "mallory-a-long-password", params.DEMO)

    doc_id = layla.upload("thesis.pdf", THESIS)
    layla.share(doc_id, "omar")
    omar.accept_shares()

    entries, _ = omar._load_keyring()
    entry = entries[doc_id]
    _hand_craft_share(omar, "omar", "mallory", doc_id, entry["manifest"],
                      entry["signature"], entry["document_key"], server)

    assert mallory.accept_shares() == []
    assert any("signature does not verify" in reason
               for reason in mallory.last_rejections), mallory.last_rejections


def test_a_manifest_addressed_elsewhere_is_refused(world):
    """The inner layer, tested on its own.

    Here everything else is consistent: the wrapping key is genuinely
    Layla's, the routing header genuinely says "layla", the signature is
    genuinely hers.  The ONLY thing wrong is that the signed manifest names
    Omar as the intended recipient, and it has been delivered to Mallory.
    This is the check that defeats surreptitious forwarding, isolated from
    every other check so we can see it fire by itself.
    """
    from securevault.crypto import ECDSA as ecdsa_module
    layla, server = world["layla"], world["server"]
    mallory = Client(server, world["ca_public"], world["ca"])
    mallory.register("mallory", "mallory-a-long-password", params.DEMO)

    doc_id = layla.upload("thesis.pdf", THESIS)
    entries, _ = layla._load_keyring()
    document_key = entries[doc_id]["document_key"]
    document = formats.decode_document(
        server.raw_object("documents", doc_id))

    manifest = formats.encode_manifest(
        manifest_id=os.urandom(16), doc_id=doc_id,
        sender="layla", recipient="omar",          # <- addressed to Omar
        plaintext_hash=__import__(
            "securevault.crypto.blake2b", fromlist=["blake2b"]
        ).blake2b(THESIS, digest_size=32),
        metadata_hash=__import__(
            "securevault.crypto.blake2b", fromlist=["blake2b"]
        ).blake2b(document["header"], digest_size=32),
        created_at=int(time.time()))
    signature = ecdsa_module.sign(layla._signing_private, manifest)

    _hand_craft_share(layla, "layla", "mallory", doc_id, manifest, signature,
                      document_key, server)     # <- delivered to Mallory

    assert mallory.accept_shares() == []
    assert any("addressed to someone else" in reason
               for reason in mallory.last_rejections), mallory.last_rejections


def test_rewriting_the_routing_header_is_rejected(world):
    """The server changes the sender name in the clear header.  The manifest
    inside the signature still says "layla", so the two disagree."""
    layla, omar, server = world["layla"], world["omar"], world["server"]
    mallory = Client(server, world["ca_public"], world["ca"])
    mallory.register("mally", "mallory-a-long-password", params.DEMO)

    doc_id = layla.upload("thesis.pdf", THESIS)
    layla.share(doc_id, "omar")

    key = [k for k in server.storage.list_keys("shares")
           if k.startswith(b"omar/")][0]
    captured = server.raw_object("shares", key)
    server.storage.put("shares", key, captured.replace(b"\x05layla", b"\x05mally"))

    assert omar.accept_shares() == []
    assert omar.last_rejections


def test_a_forged_signature_is_rejected(world):
    layla, omar, server = world["layla"], world["omar"], world["server"]
    doc_id = layla.upload("thesis.pdf", THESIS)
    layla.share(doc_id, "omar")

    key = [k for k in server.storage.list_keys("shares")
           if k.startswith(b"omar/")][0]
    captured = bytearray(server.raw_object("shares", key))
    captured[-1] ^= 0x01                      # last byte of the GCM tag
    server.storage.put("shares", key, bytes(captured))

    assert omar.accept_shares() == []
    assert any("authentication" in reason for reason in omar.last_rejections)


# =====================================================================
# Attacks on the certificate authority
# =====================================================================

def test_a_substituted_public_key_is_rejected(world):
    """The man-in-the-middle of Section 7.4: the server swaps Omar's
    certificate for one containing its own key."""
    server, layla = world["server"], world["layla"]

    rogue_ca = CertificateAuthority(str(world["root"] / "rogue-ca"))
    rogue_signing, rogue_signing_pub = P256.generate_keypair()
    rogue_agreement, rogue_agreement_pub = P256.generate_keypair()
    forged = rogue_ca.issue("omar", P256.encode_point(rogue_signing_pub),
                            P256.encode_point(rogue_agreement_pub))

    server.storage.put("certificates", "omar", forged)

    fresh = Client(server, world["ca_public"], world["ca"])
    fresh.login("layla", "layla-correct-horse-battery")
    with pytest.raises(ClientError) as error:
        fresh.certificate_for("omar")
    assert "rejected" in error.value.detail


def test_a_relabelled_certificate_is_rejected(world):
    """The server hands out Layla's genuine, CA-signed certificate when asked
    for Omar's.  The signature is valid -- but over the name "layla"."""
    server = world["server"]
    laylas = server.raw_object("certificates", "layla")
    server.storage.put("certificates", "omar", laylas)

    fresh = Client(server, world["ca_public"], world["ca"])
    fresh.login("layla", "layla-correct-horse-battery")
    with pytest.raises(ClientError):
        fresh.certificate_for("omar")


def test_fingerprints_are_stable_and_distinct(world):
    layla, omar = world["layla"], world["omar"]
    assert layla.fingerprint_of("omar") == omar.fingerprint_of("omar")
    assert layla.fingerprint_of("omar") != layla.fingerprint_of("layla")


# =====================================================================
# Login
# =====================================================================

def test_wrong_password_is_refused(world):
    fresh = Client(world["server"], world["ca_public"])
    with pytest.raises(ClientError):
        fresh.login("layla", "not-the-password")


def test_unknown_user_looks_exactly_like_a_wrong_password(world):
    """Requirement 5.2: a failed login must not reveal whether the account
    exists -- not through its message."""
    server = world["server"]

    unknown_challenge = server.login_challenge("nobody-here")
    known_challenge = server.login_challenge("layla")
    assert set(unknown_challenge) == set(known_challenge)
    assert len(unknown_challenge["salt"]) == len(known_challenge["salt"])

    # ... and the fake salt is stable, so asking twice does not give it away.
    assert server.login_challenge("nobody-here")["salt"] == unknown_challenge["salt"]

    a = b = None
    try:
        Client(server, world["ca_public"]).login("layla", "wrong")
    except ClientError as error:
        a = error.detail
    try:
        Client(server, world["ca_public"]).login("nobody-here", "wrong")
    except ClientError as error:
        b = error.detail
    assert a == b


def test_session_is_required(world):
    fresh = Client(world["server"], world["ca_public"])
    with pytest.raises(ClientError):
        fresh.upload("x.txt", b"x")


def test_duplicate_registration_is_refused(world):
    other = Client(world["server"], world["ca_public"], world["ca"])
    with pytest.raises(ServerError):
        other.register("layla", "another-password", params.DEMO)


# =====================================================================
# Password change
# =====================================================================

def test_password_change_keeps_the_identity_and_the_documents(world):
    layla, omar, server = world["layla"], world["omar"], world["server"]
    doc_id = layla.upload("thesis.pdf", THESIS)
    layla.share(doc_id, "omar")
    omar.accept_shares()

    fingerprint_before = omar.fingerprint_of("layla")
    omar.change_password("omar-a-different-long-password", "omar-brand-new-one",
                         params.DEMO)

    fresh = Client(server, world["ca_public"])
    fresh.login("omar", "omar-brand-new-one")
    assert fresh.retrieve(doc_id).plaintext == THESIS
    assert fresh.fingerprint_of("layla") == fingerprint_before

    with pytest.raises(ClientError):
        Client(server, world["ca_public"]).login("omar",
                                                 "omar-a-different-long-password")


# =====================================================================
# Access control (defence in depth, not the confidentiality mechanism)
# =====================================================================

def test_server_refuses_to_hand_ciphertext_to_a_stranger(world):
    layla, server = world["layla"], world["server"]
    mallory = Client(server, world["ca_public"], world["ca"])
    mallory.register("mallory", "mallory-a-long-password", params.DEMO)

    doc_id = layla.upload("private.txt", b"contents")
    with pytest.raises(ServerError):
        server.get_document(mallory._session, doc_id)
