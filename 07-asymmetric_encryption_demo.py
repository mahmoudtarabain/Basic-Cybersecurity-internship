

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import base64



# HELPER

def to_b64(data: bytes) -> str:
    return base64.b64encode(data).decode()



# STEP 1: Generate RSA Key Pair


def generate_rsa_keypair(bits: int = 2048):
    """
        Creates a public/private key pair.

        - PUBLIC key  → share it freely (used to encrypt)
        - PRIVATE key → keep it secret (used to decrypt)

        Args:
            bits: Key strength. 2048 = standard, 4096 = extra secure.

        Returns:
            (private_key, public_key)
        """

    private_key = RSA.generate(bits)
    public_key = private_key.publickey()
    return private_key, public_key



# STEP 2: Encrypt with Public Key


def rsa_encrypt(plaintext: str, public_key) -> bytes:
    """
       Encrypts a message using a PUBLIC key.

       Args:
           plaintext:  The message to encrypt.
           public_key: The recipient's public key.

       Returns:
           Encrypted bytes (unreadable without the private key).
       """

    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    return cipher.encrypt(plaintext.encode())



# STEP 3: Decrypt with Private Key


def rsa_decrypt(ciphertext: bytes, private_key) -> str:
    """
    Decrypts a message using the recipient's PRIVATE key.

    Args:
        ciphertext:  The encrypted bytes.
        private_key: The recipient's RSA private key (keep secret!).

    Returns:
        The original plaintext string.
    """
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    return cipher.decrypt(ciphertext).decode()



# MAIN DEMO

if __name__ == "__main__":
    message = "Hello Bob! This is Alice. Only you can read this."

    print("=" * 65)
    print("         ASYMMETRIC ENCRYPTION DEMO (RSA-2048)")
    print("=" * 65)

    #  Key Generation

    print("\n[1] Generating RSA-2048 key pair... (this may take a moment)")
    private_key, public_key = generate_rsa_keypair(2048)
    print("    Private key generated (Bob keeps this SECRET)")
    print("    Public key generated  (Bob shares this openly)\n")

    # Show PEM-encoded keys (standard format):

    print("─" * 65)
    print("PUBLIC KEY (safe to share):")
    print(public_key.export_key().decode())

    print("\nPRIVATE KEY (NEVER share this!):")
    print(private_key.export_key().decode())

    # Encryption
    print("\n─" * 65)
    print("[2] Alice encrypts her message using Bob's PUBLIC key:")
    print(f"    Original message : {message}")

    ciphertext = rsa_encrypt(message, public_key)
    print(f"    Ciphertext (b64) : {to_b64(ciphertext)[:80]}...")
    print("    (Anyone can encrypt with the public key)")

    # Decryption

    print("\n─" * 65)
    print("[3] Bob decrypts the message using his PRIVATE key:")
    decrypted = rsa_decrypt(ciphertext, private_key)
    print(f"    Decrypted message: {decrypted}")
    print(f"    Match: {message == decrypted}")

    # Wrong Key Demo
    print("\n─" * 65)
    print("[4] What if someone uses the WRONG private key?")
    wrong_private_key, _ = generate_rsa_keypair(2048)
    try:
        rsa_decrypt(ciphertext, wrong_private_key)
        print("    Decryption succeeded (this should NOT happen!)")
    except Exception as e:
        print(f"    Error (expected): {type(e).__name__}")
        print("    Only the correct private key can decrypt the message.")

    # Saving Keys to Files
    print("\n─" * 65)
    print("[5] Saving keys to PEM files (standard practice):")
    with open("private_key.pem", "wb") as f:
        f.write(private_key.export_key())
    with open("public_key.pem", "wb") as f:
        f.write(public_key.export_key())
    print("    private_key.pem  — saved (protect this file!)")
    print("    public_key.pem   — saved (share this freely)")

    # Loading Keys Back

    print("\n[6] Loading keys back from PEM files and re-decrypting:")
    with open("private_key.pem", "rb") as f:
        loaded_private = RSA.import_key(f.read())
    result = rsa_decrypt(ciphertext, loaded_private)
    print(f"    Decrypted from loaded key: {result}")
    print(f"    Match: {message == result}")

    print("\n" + "=" * 65)
    print("  KEY TAKEAWAYS:")
    print("  * Public key encrypts  — share it with the world")
    print("  * Private key decrypts — NEVER share it")
    print("  * RSA-2048 is the minimum; RSA-4096 for high security")
    print("  * OAEP padding is mandatory — never use raw/textbook RSA")
    print("  * RSA is SLOW — in practice, used to encrypt a symmetric")
    print("    key (e.g. AES), which then encrypts the actual data")
    print("=" * 65)
