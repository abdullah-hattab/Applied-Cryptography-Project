
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from securevault import params  # noqa: E402
from securevault.crypto import kdf  # noqa: E402


def _master(password="correct horse battery staple", salt=b"\x00" * 16):
    return kdf.derive_master_key(password, salt, params.DEMO)


def test_auth_token_and_vault_key_are_unrelated():

    master = _master()
    token = kdf.derive_auth_token(master)
    vault = kdf.derive_vault_key(master)

    assert token != vault
    assert not token.startswith(vault)
    assert not vault.startswith(token[:len(vault)])


def test_vault_key_is_an_aes128_key():
    assert len(kdf.derive_vault_key(_master())) == params.SYMMETRIC_KEY_SIZE


def test_verifier_does_not_reveal_the_token():

    master = _master()
    token = kdf.derive_auth_token(master)
    assert kdf.derive_verifier(token) != token


def test_different_passwords_give_different_everything():
    a = _master("password one")
    b = _master("password two")
    assert kdf.derive_auth_token(a) != kdf.derive_auth_token(b)
    assert kdf.derive_vault_key(a) != kdf.derive_vault_key(b)


def test_same_password_different_salt_gives_different_master():

    a = kdf.derive_master_key("shared password", os.urandom(16), params.DEMO)
    b = kdf.derive_master_key("shared password", os.urandom(16), params.DEMO)
    assert a != b


def test_derivation_is_deterministic():
    salt = os.urandom(16)
    first = kdf.derive_auth_token(kdf.derive_master_key("pw", salt, params.DEMO))
    second = kdf.derive_auth_token(kdf.derive_master_key("pw", salt, params.DEMO))
    assert first == second


@pytest.mark.slow
def test_profiles_are_not_interchangeable():

    salt = os.urandom(16)
    demo = kdf.derive_master_key("pw", salt, params.DEMO)
    production = kdf.derive_master_key("pw", salt, params.PRODUCTION)
    assert demo != production


def test_kek_is_bound_to_the_parties_and_the_document():

    shared = os.urandom(32)
    doc = os.urandom(16)

    base = kdf.derive_kek(shared, "layla", "omar", doc)
    assert kdf.derive_kek(shared, "layla", "omar", os.urandom(16)) != base
    assert kdf.derive_kek(shared, "layla", "mallory", doc) != base
    assert kdf.derive_kek(shared, "mallory", "omar", doc) != base

    assert kdf.derive_kek(shared, "omar", "layla", doc) != base


def test_identity_concatenation_is_unambiguous():

    shared, doc = os.urandom(32), os.urandom(16)
    assert kdf.derive_kek(shared, "ab", "c", doc) != kdf.derive_kek(shared, "a", "bc", doc)


def test_every_label_gives_a_distinct_output():
    secret = os.urandom(32)
    labels = [params.LABEL_AUTH_TOKEN, params.LABEL_VAULT_KEY,
              params.LABEL_VERIFIER, params.LABEL_KEK,
              params.LABEL_SIG_DIGEST, params.LABEL_NONCE_PRF,
              params.LABEL_FINGERPRINT, params.LABEL_CERT_DIGEST]
    outputs = {kdf.derive(secret, label) for label in labels}
    assert len(outputs) == len(labels)


def test_all_labels_fit_blake2b_personalisation():
    for label in (params.LABEL_AUTH_TOKEN, params.LABEL_VAULT_KEY,
                  params.LABEL_VERIFIER, params.LABEL_KEK,
                  params.LABEL_SIG_DIGEST, params.LABEL_NONCE_PRF,
                  params.LABEL_FINGERPRINT, params.LABEL_CERT_DIGEST):
        assert len(label) <= 16, label


def test_derive_rejects_oversized_inputs():
    with pytest.raises(ValueError):
        kdf.derive(os.urandom(65), params.LABEL_KEK)
    with pytest.raises(ValueError):
        kdf.derive(os.urandom(32), b"a personalisation string that is too long")


def test_fingerprint_is_stable_and_readable():
    public_key = os.urandom(65)
    assert kdf.fingerprint(public_key) == kdf.fingerprint(public_key)
    assert kdf.fingerprint(public_key) != kdf.fingerprint(os.urandom(65))

    shown = kdf.format_fingerprint(public_key)
    assert shown == kdf.format_fingerprint(public_key)
    assert len(shown.split()) == 8          # eight groups a human can read
    assert all(len(group) == 4 for group in shown.split())
