"""Shared setup for the attack programs.

Every script in this directory builds its own throwaway world -- its own CA,
its own server, its own users -- inside a temporary directory, runs one
attack against it, and reports what happened.

ACADEMIC INTEGRITY NOTE, as Section 12.2 requires: all of this code targets
only our own system, running locally in a temporary directory.  Nothing here
touches university infrastructure or any third-party service, and none of it
makes a network connection of any kind.
"""

import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from securevault import params                                    # noqa: E402
from securevault.ca import CertificateAuthority                   # noqa: E402
from securevault.client import Client                             # noqa: E402
from securevault.crypto import P256                               # noqa: E402
from securevault.server import Server                             # noqa: E402

THESIS = (b"CONFIDENTIAL: thesis draft, chapter 3.\n"
          b"The results in table 2 have not been published.\n") * 8


class World:
    """A CA, a server, and Layla and Omar, in a temporary directory."""

    def __init__(self):
        self.root = tempfile.mkdtemp(prefix="securevault-attack-")
        self.ca = CertificateAuthority(os.path.join(self.root, "ca"))
        self.ca_public = P256.decode_point(self.ca.export_trust_anchor())
        self.server = Server(os.path.join(self.root, "server"), self.ca_public)

        self.layla = Client(self.server, self.ca_public, self.ca)
        self.omar = Client(self.server, self.ca_public, self.ca)
        self.layla.register("layla", "layla-a-long-password", params.DEMO)
        self.omar.register("omar", "omar-a-long-password", params.DEMO)

    def share_a_document(self, filename="thesis-draft.pdf", data=THESIS):
        doc_id = self.layla.upload(filename, data, "application/pdf")
        self.layla.share(doc_id, "omar")
        return doc_id

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)


def banner(title):
    print()
    print("=" * 72)
    print(f"  {title}")
    print("=" * 72)


def step(text):
    print(f"\n  >> {text}")


def result(succeeded, text):
    marker = "ATTACK SUCCEEDED" if succeeded else "attack failed"
    print(f"\n  [{marker}] {text}")


def run(attack):
    world = World()
    try:
        attack(world)
    finally:
        world.cleanup()
