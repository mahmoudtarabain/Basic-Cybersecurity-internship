

from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64



# HELPER: pretty print bytes as Base64

def to_b64(data: bytes) -> str:
    return base64.b64encode(data).decode()



# 1. AES ENCRYPTION (AES-256 in CBC mode)


def aes_encrypt(plaintext: str, key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypts a plaintext string using AES-256 CBC mode.

    Args:
        plaintext: The message to encrypt.
        key:       A 32-byte (256-bit) secret key.

    Returns:
        (iv, ciphertext) — both needed for decryption.
    """
    cipher = AES.new(key, AES.MODE_CBC)          # CBC mode auto-generates an IV
    padded = pad(plaintext.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded)
    return cipher.iv, ciphertext


def aes_decrypt(iv: bytes, ciphertext: bytes, key: bytes) -> str:
    """
    Decrypts AES-256 CBC ciphertext back to plaintext.

    Args:
        iv:         Initialization vector used during encryption.
        ciphertext: Encrypted bytes.
        key:        The same 32-byte key used for encryption.

    Returns:
        The original plaintext string.
    """
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    padded = cipher.decrypt(ciphertext)
    return unpad(padded, AES.block_size).decode()



# 2. DES ENCRYPTION (DES in CBC mode)
# DES is 56-bit — INSECURE, shown for educational purposes only


def des_encrypt(plaintext: str, key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypts a plaintext string using DES CBC mode.
    NOTE: DES key must be exactly 8 bytes (64 bits, 56 effective).

    Args:
        plaintext: The message to encrypt.
        key:       An 8-byte DES key.

    Returns:
        (iv, ciphertext)
    """
    cipher = DES.new(key, DES.MODE_CBC)
    padded = pad(plaintext.encode(), DES.block_size)
    ciphertext = cipher.encrypt(padded)
    return cipher.iv, ciphertext


def des_decrypt(iv: bytes, ciphertext: bytes, key: bytes) -> str:
    """
    Decrypts DES CBC ciphertext back to plaintext.
    """
    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    padded = cipher.decrypt(ciphertext)
    return unpad(padded, DES.block_size).decode()



# MAIN DEMO

if __name__ == "__main__":
    message = "Hello, Cybersecurity World! This is a secret message."
    print("=" * 60)
    print("       SYMMETRIC ENCRYPTION DEMO")
    print("=" * 60)
    print(f"\n  Original Message : {message}\n")

    # AES Demo
    print("─" * 60)
    print(" AES-256 (CBC Mode)  — Recommended Standard")
    print("─" * 60)

    aes_key = get_random_bytes(32)          # 256-bit key
    iv, ciphertext = aes_encrypt(message, aes_key)

    print(f"  Key (hex)        : {aes_key.hex()}")
    print(f"  IV  (hex)        : {iv.hex()}")
    print(f"  Ciphertext (b64) : {to_b64(ciphertext)}")

    decrypted = aes_decrypt(iv, ciphertext, aes_key)
    print(f"  Decrypted        : {decrypted}")
    print(f"   Match         : {message == decrypted}\n")

    # DES Demo
    print("─" * 60)
    print("  DES (CBC Mode)  — Legacy / Educational Only")
    print("─" * 60)

    des_key = get_random_bytes(8)           # 64-bit key (56 effective)
    iv_des, ct_des = des_encrypt(message, des_key)

    print(f"  Key (hex)        : {des_key.hex()}")
    print(f"  IV  (hex)        : {iv_des.hex()}")
    print(f"  Ciphertext (b64) : {to_b64(ct_des)}")

    decrypted_des = des_decrypt(iv_des, ct_des, des_key)
    print(f"  Decrypted        : {decrypted_des}")
    print(f"   Match         : {message == decrypted_des}\n")

    # Wrong Key Demo

    print("─" * 60)
    print(" Wrong Key Demo  What happens with wrong key?")
    print("─" * 60)

    wrong_key = get_random_bytes(32)
    try:
        aes_decrypt(iv, ciphertext, wrong_key)
        print("  Decryption succeeded (unexpected!)")
    except Exception as e:
        print(f"  Error (expected): {type(e).__name__} — {e}")

    print("\n" + "=" * 60)
    print("  KEY TAKEAWAYS:")
    print("  • Same key encrypts AND decrypts (symmetric)")
    print("  • AES-256 is the modern standard — use it!")
    print("  • DES is broken — 56-bit key can be brute-forced")
    print("  • IV (Initialization Vector) ensures unique ciphertexts")
    print("  • Never share the key over an insecure channel!")
    print("=" * 60)
