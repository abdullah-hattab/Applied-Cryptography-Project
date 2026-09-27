from __future__ import annotations

import os


class Storage:
    """A directory of named blobs, grouped into collections."""

    def __init__(self, root: str):
        self.root = os.path.abspath(root)
        os.makedirs(self.root, exist_ok=True)

    # -- key handling ----------------------------------------------------
    #
    # Keys come from user input (usernames, document identifiers), so they are
    # hex-encoded before they touch the filesystem.  A username of "../../etc"
    # would otherwise escape the storage directory entirely; hex encoding
    # makes every key a flat string of [0-9a-f] with no separators, no dots
    # and no case-sensitivity surprises on filesystems that fold case.

    @staticmethod
    def _encode_key(key) -> str:
        if isinstance(key, str):
            key = key.encode("utf-8")
        return key.hex()

    @staticmethod
    def _decode_key(name: str) -> bytes:
        return bytes.fromhex(name)

    def _path(self, collection: str, key) -> str:
        if not collection.isalnum():
            raise ValueError("collection names must be alphanumeric")
        directory = os.path.join(self.root, collection)
        os.makedirs(directory, exist_ok=True)
        return os.path.join(directory, self._encode_key(key))

    # -- operations ------------------------------------------------------

    def put(self, collection: str, key, data: bytes) -> None:
        path = self._path(collection, key)
        # Write to a temporary file and rename, so a reader never sees a
        # half-written object.  Not a security property -- just the difference
        # between a crash losing one write and a crash corrupting the store.
        temporary = path + ".tmp"
        with open(temporary, "wb") as handle:
            handle.write(data)
        os.replace(temporary, path)

    def get(self, collection: str, key) -> bytes:
        try:
            with open(self._path(collection, key), "rb") as handle:
                return handle.read()
        except FileNotFoundError:
            return None

    def exists(self, collection: str, key) -> bool:
        return os.path.exists(self._path(collection, key))

    def delete(self, collection: str, key) -> None:
        try:
            os.remove(self._path(collection, key))
        except FileNotFoundError:
            pass

    def list_keys(self, collection: str) -> list:
        directory = os.path.join(self.root, collection)
        if not os.path.isdir(directory):
            return []
        return sorted(self._decode_key(name) for name in os.listdir(directory)
                      if not name.endswith(".tmp"))

    def path_of(self, collection: str, key) -> str:
        return self._path(collection, key)
