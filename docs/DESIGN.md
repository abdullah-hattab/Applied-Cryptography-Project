SecureVault- Section 7 Design Decision

ENCS4320 — Applied Cryptography, Term 1253

Team: abdallah hattab -1230588|	abdallah murra - 1230534|	osama aabed  -1201164

7.1 — Password protection Argon2id. Parameters m, t, p set by measurement (target ≈ 0.25 s per verification). 16-byte per-user salt from the OS CSPRNG, stored in the clear.

7.2 — Document contents AES-128-GCM (AES-CTR + GHASH). A fresh random key per document, so each key encrypts exactly one message. Metadata carried in the AAD.

7.3 — Public-key cryptography ECDH on NIST P-256 for key agreement; ECDSA on NIST P-256 for signatures. Message digest: BLAKE2b-256. Signature nonce k: deterministic, RFC 6979 construction with keyed BLAKE2b as the PRF. Security level: 128-bit throughout (AES-128 ↔ P-256 ↔ 128-bit GCM tag).

7.4 — Trusting a public key A certificate authority implemented by the team, signing user public keys at registration. Key fingerprints displayed in the client for optional out-of-band verification.

7.5 — Signatures vs MACs GCM tag for integrity and metadata binding. ECDSA signature for data-origin authentication and non-repudiation. Sign-then-encrypt, with the intended recipient's identity inside the signed region. Signed manifest: sender ‖ recipient ‖ BLAKE2b-256(plaintext) ‖ metadata ‖ freshness value.

7.6 — Architecture Client and server communicating through a shared directory (simulated network).

Domain separation: BLAKE2b serves several roles (Argon2, KDF, ECDSA digest, nonce PRF, fingerprints), each with a distinct personalization string.

Implemented from scratch: BLAKE2b, Argon2id, AES-128, CTR, GHASH, GCM, P-256 arithmetic, ECDH, ECDSA, KDF. From libraries: big-integer arithmetic, OS randomness, file I/O, networking, interface code.
