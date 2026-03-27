

from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
import base64



# HELPER

def to_b64(data: bytes) -> str:
    return base64.b64encode(data).decode()



# STEP 1: Generate RSA Key Pair


def generate_keypair(bits: int = 2048):
    """Generates an RSA key pair for signing."""
    private_key = RSA.generate(bits)
    public_key = private_key.publickey()
    return private_key, public_key



# STEP 2: Sign a Message (uses PRIVATE key)


def sign_message(message: str, private_key) -> bytes:

 """
This function creates a digital signature for a message.

It hashes the message using SHA-256, then signs it with my RSA private key (RSA-PSS).

Args:
    message: The message I want to sign.
    private_key: My RSA private key.

Returns:
    The digital signature as bytes.
"""

    msg_hash = SHA256.new(message.encode())
    signature = pss.new(private_key).sign(msg_hash)
    return signature



# STEP 3: Verify a Signature (uses PUBLIC key)


def verify_signature(message: str, signature: bytes, public_key) -> bool:

   """
This function verifies if a digital signature is valid.

It hashes the message using SHA-256, then checks the signature using the sender’s public key.

Args:
    message: The received message.
    signature: The signature to verify.
    public_key: The sender’s RSA public key.

Returns:
    True if the signature is valid, otherwise False.
"""

    try:
        msg_hash = SHA256.new(message.encode())
        pss.new(public_key).verify(msg_hash, signature)
        return True
    except (ValueError, TypeError):
        return False



# MAIN DEMO

if __name__ == "__main__":

    print("=" * 65)
    print("           DIGITAL SIGNATURES DEMO (RSA-PSS)")
    print("=" * 65)

    # Key Generation
    print("\n[1] Alice generates her RSA-2048 key pair...")
    alice_private, alice_public = generate_keypair(2048)
    print("    Private key: Alice keeps this SECRET (used to SIGN)")
    print("    Public key:  Alice shares this openly (used to VERIFY)")

    # Signing
    print("\n─" * 65)
    original_message = "Transfer $500 to Bob. Authorized by Alice."
    print(f"\n[2] Alice signs her message:")
    print(f"    Message   : {original_message}")

    signature = sign_message(original_message, alice_private)
    print(f"    Signature : {to_b64(signature)[:72]}...")
    print("    (Signature created using Alice's PRIVATE key)")

    # Verification -- Valid
    print("\n─" * 65)
    print("\n[3] Bob receives the message and verifies Alice's signature:")
    is_valid = verify_signature(original_message, signature, alice_public)
    print(f"    Verification result: {'VALID ' if is_valid else 'INVALID '}")
    print("    Message is authentic — definitely from Alice, unmodified.")

    # Tampered Message
    print("\n─" * 65)
    tampered_message = "Transfer $50000 to Bob. Authorized by Alice."
    print(f"\n[4] Eve tampers with the message in transit:")
    print(f"    Original : {original_message}")
    print(f"    Tampered : {tampered_message}")

    is_valid_tampered = verify_signature(tampered_message, signature, alice_public)
    print(f"\n    Verification result: {'VALID ' if is_valid_tampered else 'INVALID  — Tampering detected!'}")
    print("    Even a single character change breaks the signature.")

    # Wrong Signer
    print("\n─" * 65)
    print("\n[5] What if Eve tries to forge Alice's signature?")
    eve_private, eve_public = generate_keypair(2048)
    forged_signature = sign_message(original_message, eve_private)  # Eve signs with HER key

    is_valid_forged = verify_signature(original_message, forged_signature, alice_public)
    print(f"    Verification with Alice's public key: {'VALID ' if is_valid_forged else 'INVALID  — Forgery detected!'}")
    print("    Only Alice's private key produces a valid signature for her public key.")

    # Signing is NOT Encryption
    print("\n─" * 65)
    print("\n[6] Key reminder: Signing is NOT the same as encryption!")
    print("    Signing   → Private key signs,  Public key verifies  (authenticity)")
    print("    Encryption→ Public key encrypts, Private key decrypts (confidentiality)")
    print("    A signed message is still READABLE by everyone.")
    print("    For confidential + authenticated messages, do BOTH.")

    # Save keys
    print("\n─" * 65)
    print("\n[7] Saving Alice's keys to PEM files:")
    with open("alice_private.pem", "wb") as f:
        f.write(alice_private.export_key())
    with open("alice_public.pem", "wb") as f:
        f.write(alice_public.export_key())
    print("    alice_private.pem — saved (Alice keeps SECRET)")
    print("    alice_public.pem  — saved (Alice shares openly)")

    print("\n" + "=" * 65)
    print("  KEY TAKEAWAYS:")
    print("  * Private key SIGNS   — proves the message came from you")
    print("  * Public key VERIFIES — anyone can confirm authenticity")
    print("  * Hashing ensures integrity — any change breaks the sig")
    print("  * RSA-PSS is the secure padding scheme — always use it")
    print("  * Signing does NOT encrypt — message is still readable")
    print("  * Used in: code signing, SSL certs, emails (S/MIME, PGP)")
    print("=" * 65)
