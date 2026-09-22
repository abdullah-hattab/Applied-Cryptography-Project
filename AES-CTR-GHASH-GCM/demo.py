
import secrets

from gcm import AuthenticationError, decrypt, encrypt


def main():
    key = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    # Integration code must define one canonical metadata encoding.
    metadata = b'{"name":"notes.txt","owner":"student1","version":1}'
    original = b"These are my private project notes."
    ciphertext, tag = encrypt(key, nonce, original, metadata)
    print("Ciphertext:", ciphertext.hex())
    print("Tag:", tag.hex())
    print("Recovered:", decrypt(key, nonce, ciphertext, tag, metadata).decode())
    changed = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
    try:
        decrypt(key, nonce, changed, tag, metadata)
    except AuthenticationError:
        print("Modified ciphertext rejected.")
    try:
        decrypt(key, nonce, ciphertext, tag, metadata.replace(b"notes", b"other"))
    except AuthenticationError:
        print("Modified metadata rejected.")


if __name__ == "__main__":
    main()
