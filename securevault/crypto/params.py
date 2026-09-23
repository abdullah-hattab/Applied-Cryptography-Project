

from __future__ import annotations


WIRE_VERSION = 1           # bumping this invalidates every stored object

# ----------------------------------------------------- Argon2id work factors
#
# THE MEASUREMENT AND WHY THERE ARE TWO PROFILES
#
# Our Argon2id is written from scratch in Python, as the project rules
# require.  Measured on the development machine, it is about 290x slower than
# the reference C implementation for identical parameters (m=1 MiB, t=1, p=1:
# 260 ms for ours, 0.9 ms for the reference).  Run tools/bench.py to reproduce
# these numbers on your own hardware -- the figures in the report are the ones
# that script prints, not these comments.
#
# That gap forces a decision.  If we set the work factor so that OUR
# verification takes 0.25 s, we land on m = 1 MiB -- which an attacker using
# compiled Argon2 computes in 0.9 ms, roughly 1,100 guesses per second per
# core.  Tuning to our own speed would therefore have produced a parameter set
# chosen by our implementation's weakness rather than by the attacker's cost.
# The work factor has to be argued from the attacker's side of the table.
#
# So we define the real parameter set (PRODUCTION) at RFC 9106's second
# recommended option, and a reduced one (DEMO) used only to keep the live
# demonstration responsive.  The report quantifies the offline attack against
# BOTH, and says plainly which one the demo ran under.  Nothing is hidden:
# the profile name is written into every credential record, so the stored
# data itself shows which parameters produced it.

class Argon2Profile:
    def __init__(self, name, memory_cost, time_cost, parallelism):
        self.name = name
        self.memory_cost = memory_cost      # KiB
        self.time_cost = time_cost          # passes
        self.parallelism = parallelism      # lanes

    def __repr__(self):
        return (f"Argon2Profile({self.name!r}, m={self.memory_cost} KiB, "
                f"t={self.time_cost}, p={self.parallelism})")


# RFC 9106 section 4, second recommended option.  Reference C: ~164 ms.
PRODUCTION = Argon2Profile("production", memory_cost=65536, time_cost=3,
                           parallelism=4)

# Live-demonstration profile only.  Our Python: ~260 ms.  Below RFC 9106's
# recommended floor, and the report says so under limitations.
DEMO = Argon2Profile("demo", memory_cost=1024, time_cost=1, parallelism=1)

PROFILES = {p.name: p for p in (PRODUCTION, DEMO)}
DEFAULT_PROFILE = DEMO

SALT_SIZE = 16             # 128 bits: collision probability is negligible
                           # across any realistic user population, and RFC 9106
                           # recommends exactly this.  The salt is NOT secret --
                           # its only job is to make each user's hash a
                           # separate problem, so that one precomputed table
                           # cannot attack the whole database at once.

# ----------------------------------------------------------------- key sizes

MASTER_KEY_SIZE = 32       # Argon2id output
SYMMETRIC_KEY_SIZE = 16    # AES-128
GCM_NONCE_SIZE = 12
GCM_TAG_SIZE = 16
FINGERPRINT_SIZE = 32      # BLAKE2b-256 over the encoded public key

# ------------------------------------------------- domain-separation labels
#
# BLAKE2b does five different jobs in this system.  Each one gets its own
# 16-byte personalisation string, which BLAKE2b mixes into its initial state.
# The effect is that the same input hashed in two roles gives unrelated
# outputs, so a value produced for one purpose can never be replayed as a
# value for another.  Without this, for example, an ECDSA digest and a KDF
# output over the same bytes would be the same number.

LABEL_AUTH_TOKEN = b"SV-AUTH-v1"      # master -> token the server checks
LABEL_VAULT_KEY = b"SV-VAULT-v1"      # master -> key that unwraps private keys
LABEL_VERIFIER = b"SV-VERIF-v1"       # token  -> what the server actually stores
LABEL_KEK = b"SV-KEK-v1"              # ECDH shared secret -> key-wrapping key
LABEL_SIG_DIGEST = b"SV-SIGDGST1"     # message -> ECDSA digest
LABEL_NONCE_PRF = b"SV-6979-PRF"      # RFC 6979 deterministic k
LABEL_FINGERPRINT = b"SV-FPRINT-1"    # public key -> fingerprint shown to users
LABEL_CERT_DIGEST = b"SV-CERT-v1"     # certificate body -> digest the CA signs

# --------------------------------------------------------------- usernames
#
# Usernames are restricted to lowercase ASCII letters, digits, underscore and
# hyphen.  This is a security decision, not a tidiness one, and we found the
# need for it by attacking our own system.
#
# Our first version accepted any Python identifier.  Python identifiers may
# contain Unicode letters, so "omаr" -- with a CYRILLIC small a -- is a
# perfectly legal and completely distinct username that renders on screen
# exactly like "omar".  An attacker registers it, the CA signs it without
# complaint (it is a genuinely new name with a genuinely new key), and Layla
# reading her own screen cannot tell which one she is sharing with.  Every
# cryptographic guarantee in the system would hold perfectly while the
# document went to the wrong person.
#
# Restricting the alphabet closes the Unicode form of this.  It does NOT close
# the ASCII form: "rnark" against "mark", "l" against "1", "0" against "o".
# Those remain possible and are named in the report's limitations, with
# fingerprint comparison as what a careful user can do about it.

USERNAME_MAX_LENGTH = 64
USERNAME_ALPHABET = frozenset("abcdefghijklmnopqrstuvwxyz0123456789_-")


def is_valid_username(username) -> bool:
    return (isinstance(username, str)
            and 1 <= len(username) <= USERNAME_MAX_LENGTH
            and set(username) <= USERNAME_ALPHABET)


# -------------------------------------------------------------- freshness
#
# How long a signed manifest is accepted after its stated timestamp.  Short
# enough that a captured object is stale quickly; long enough to tolerate
# clock skew between two machines that were never synchronised.  The window
# alone is not what stops replay -- the recipient also records every manifest
# identifier it has accepted -- but it bounds how large that record must grow.

FRESHNESS_WINDOW_SECONDS = 300
