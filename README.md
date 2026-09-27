# SecureVault

A multi-user encrypted document exchange system for an untrusted server.

ENCS4320 — Applied Cryptography, Term 1253
Birzeit University, Faculty of Engineering and Technology

## Team

| Name | Student ID |
|---|---|
| Abdallah Hattab | 1230588 |
| Abdallah Murra | 1230534 |
| Osama Aabed | 1201164 |

## What it does

Users store documents on a server that never sees their contents, and share
them with each other. The recipient learns who produced a document and can
prove it to a third party. Any modification — to the ciphertext, to the
metadata, or to the claimed sender — is detected and refused, and a replayed
object is rejected as stale.

The design decisions and the reasoning behind them are in
[`design-report.pdf`](design-report.pdf). The byte-level formats are
in [`securevault/formats.py`](securevault/formats.py), documented field by
field.

## Requirements

Python 3.9 or later. No third-party packages are needed to **run** the
system. Two optional packages are used by the test suite for cross-checking
against reference implementations, and the suite skips those tests cleanly if
they are absent:

```bash
pip install pytest                    # to run the tests
pip install cryptography argon2-cffi  # optional: reference cross-checks
```

## Running the tests

```bash
pytest -m "not slow"     # the full suite, about 35 seconds
pytest                   # adds one test at the production Argon2id work
                         # factor, which takes about 40 seconds on its own
```

Every primitive we implemented is tested against published vectors — RFC 7693
(BLAKE2b), FIPS 197 (AES), the McGrew–Viega cases (GCM), RFC 9106 (Argon2),
RFC 6979 (ECDSA nonces and signatures) — and additionally diffed against
reference libraries over random inputs where those libraries are installed.

## Running the demonstration

Walks through all nine requirements of Section 8 in order, driving the real
command-line client:

```bash
python3 demo/run_demo.py             # straight through
python3 demo/run_demo.py --pause     # stop between steps
```

## Running the attacks

Each program builds its own throwaway world, attacks it, and reports what
happened. They target only this system, locally, and make no network
connections.

```bash
cd attacks
python3 attack_mitm.py               # public key substitution
python3 attack_tamper.py             # ciphertext and metadata tampering
python3 attack_replay.py             # replay
python3 attack_weak_nonce.py         # a weakened build, broken
python3 attack_offline_guessing.py   # how long an offline attack would take
```

`attack_weak_nonce.py` is the one worth reading: it builds a copy of the
client with the nonce discipline removed, recovers a confidential document in
full against it, and then fails against the correct build.

## Using it

```bash
# One-time setup: create the certificate authority and the server storage.
python3 -m securevault.cli init

# Two users register.  Each gets a key pair and a CA-signed certificate.
python3 -m securevault.cli register --user layla --password 'a long passphrase'
python3 -m securevault.cli register --user omar  --password 'another long one'

# Layla uploads and shares.
python3 -m securevault.cli upload --user layla --password '...' \
    --file thesis-draft.pdf --mimetype application/pdf
python3 -m securevault.cli share  --user layla --password '...' \
    --doc <document-id> --to omar

# Omar accepts the share and opens the document.
python3 -m securevault.cli inbox --user omar --password '...'
python3 -m securevault.cli get   --user omar --password '...' \
    --doc <document-id> --out thesis.pdf --receipt omar.receipt

# A third party checks the evidence, holding only the CA's public key.
python3 -m securevault.cli verify-receipt --receipt omar.receipt

# See what the server actually stores.
python3 -m securevault.cli inspect --collection credentials --key layla
python3 -m securevault.cli inspect --collection documents --key <document-id>

# Compare fingerprints out of band, as a second layer above the CA.
python3 -m securevault.cli fingerprint --user layla --password '...' --of omar
```

Add `--profile production` to `register` for the real Argon2id work factor.
It takes about 40 seconds per login in our pure-Python implementation; see
"A note on the work factor" below.

## Measurements

The numbers in the report come from these scripts, run on the machine the
report describes. Re-run them on your own hardware rather than quoting ours.

```bash
python3 tools/bench.py       # Argon2id: ours vs the reference implementation
python3 tools/bench_ec.py    # P-256 vs finite-field Diffie-Hellman
```

## A note on the work factor

Our Argon2id is written from scratch in Python, as the project rules require,
and is roughly 300× slower than the compiled reference implementation for
identical parameters. Tuning the work factor so that *our* verification takes
a quarter of a second would have chosen the parameters by our implementation's
weakness rather than by the attacker's cost — and would have produced a
setting an attacker computes in under a millisecond.

So there are two profiles. `production` uses RFC 9106's recommended
parameters and is what the design specifies. `demo` is reduced so the live
demonstration stays responsive. The profile name is recorded in every
credential record, so the stored data itself shows which was used, and the
report quantifies the offline attack against both. This is discussed in
`securevault/params.py` and measured by `attacks/attack_offline_guessing.py`.

## Layout

```
securevault/
  crypto/          primitives we implemented: blake2b, aes, gcm, argon2,
                   p256, ecdsa, ecdh, kdf
  params.py        every tunable number, with its reasoning
  formats.py       byte-level formats for every stored and transmitted object
  storage.py       the shared directory that simulates the network
  ca.py            the certificate authority
  server.py        the honest-but-curious server
  client.py        all cryptographic decisions
  cli.py           command-line interface
tests/             the test suite
attacks/           attack programs (Section 12.2)
demo/run_demo.py   the scripted demonstration (Section 8)
tools/             measurement scripts
docs/              design report and presentation slides
```

## What we implemented, and what we took from libraries

Implemented from scratch, with no cryptographic library: BLAKE2b, Argon2id,
AES-128, CTR mode, GHASH, AES-GCM, P-256 field and curve arithmetic, ECDH,
ECDSA with RFC 6979 deterministic nonces, and the key-derivation hierarchy.

Taken from libraries: Python's arbitrary-precision integers, `os.urandom` for
randomness, and the file, argument-parsing and interface code. The project
rules classify these as non-cryptographic components.

Used in the test suite only, for cross-checking: `hashlib`, `hmac`,
`cryptography`, `argon2-cffi`. No production code path imports any of them.
Section 4 of the design report accounts for this against the 70% rule.

## AI usage

Declared in full in section 6 of `/design-report.pdf`.
