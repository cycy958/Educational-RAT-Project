"""
crypto_utils.py

Module de chiffrement/déchiffrement AES-256-CBC pour les communications C2.

Utilise la bibliothèque cryptography pour le chiffrement symétrique.
La clé AES-256 doit être identique à celle stockée dans le client C++.

Educational Project - Cybersecurity Engineering
Purpose: Educational study of secure network protocols and encryption
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os

# ⚠️ PLACEHOLDER KEY - Replace with your own key
# Generate with: python -c "import os; print([hex(b) for b in os.urandom(32)])"
AES_KEY = bytes([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
])


def encrypt(plaintext: str, key: bytes = None) -> str:
    """
    Chiffre une chaîne avec AES-256-CBC et retourne Base64(IV + ciphertext).

    Processus :
    1. Génère un IV aléatoire (16 bytes)
    2. Applique un padding PKCS7 au plaintext
    3. Chiffre avec AES-256-CBC
    4. Concatène IV + ciphertext
    5. Encode le tout en Base64

    Args:
        plaintext: Texte en clair à chiffrer (string)
        key: Clé AES-256 (32 bytes) optionnelle. Si None, utilise la clé par défaut.

    Returns:
        Chaîne Base64 contenant IV + ciphertext

    Example:
        >>> encrypted = encrypt('{"status": "ok"}')
        >>> print(len(encrypted))
        > 50  # Dépend de la longueur du plaintext
    """
    # Utiliser la clé fournie ou la clé par défaut
    if key is None:
        key = AES_KEY

    # Générer un IV aléatoire (16 bytes)
    iv = os.urandom(16)

    # Créer le cipher AES-256-CBC
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()

    # Appliquer padding PKCS7
    plaintext_bytes = plaintext.encode('utf-8')
    padding_len = 16 - (len(plaintext_bytes) % 16)
    padded = plaintext_bytes + bytes([padding_len] * padding_len)

    # Chiffrer
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    # Concaténer IV + ciphertext et encoder en Base64
    result = iv + ciphertext
    return base64.b64encode(result).decode('utf-8')


def decrypt(b64_data: str, key: bytes = None) -> str:
    """
    Déchiffre une chaîne Base64(IV + ciphertext) et retourne le plaintext.

    Processus :
    1. Décode le Base64
    2. Extrait l'IV (16 premiers bytes)
    3. Extrait le ciphertext (bytes restants)
    4. Déchiffre avec AES-256-CBC
    5. Retire le padding PKCS7
    6. Retourne le plaintext UTF-8

    Args:
        b64_data: Données chiffrées en Base64 (string)
        key: Clé AES-256 (32 bytes) optionnelle. Si None, utilise la clé par défaut.

    Returns:
        Texte en clair déchiffré (string)

    Raises:
        Exception: Si le déchiffrement échoue (mauvaise clé, données corrompues, etc.)

    Example:
        >>> encrypted = encrypt('test')
        >>> decrypted = decrypt(encrypted)
        >>> assert decrypted == 'test'
    """
    try:
        # Utiliser la clé fournie ou la clé par défaut
        if key is None:
            key = AES_KEY

        # Décoder le Base64
        data = base64.b64decode(b64_data)

        if len(data) < 16:
            raise ValueError("Données trop courtes pour contenir un IV")

        # Extraire IV (16 premiers bytes)
        iv = data[:16]

        # Extraire ciphertext (reste des bytes)
        ciphertext = data[16:]

        # Créer le cipher AES-256-CBC
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()

        # Déchiffrer
        padded = decryptor.update(ciphertext) + decryptor.finalize()

        # Retirer le padding PKCS7
        padding_len = padded[-1]

        # Vérifier que le padding est valide
        if padding_len == 0 or padding_len > 16:
            raise ValueError("Padding PKCS7 invalide")

        # Vérifier que tous les bytes de padding ont la bonne valeur
        for i in range(1, padding_len + 1):
            if padded[-i] != padding_len:
                raise ValueError("Padding PKCS7 corrompu")

        # Retirer le padding et décoder UTF-8
        plaintext_bytes = padded[:-padding_len]
        return plaintext_bytes.decode('utf-8', errors='replace')

    except Exception as e:
        print(f"[CRYPTO ERROR] Déchiffrement échoué: {e}")
        raise


def is_encrypted(data: str) -> bool:
    """
    Vérifie si une chaîne ressemble à des données chiffrées en Base64.

    Cette fonction essaie de déterminer si la chaîne est du Base64 valide
    et a une longueur cohérente avec des données chiffrées AES-CBC.

    Args:
        data: Chaîne à vérifier

    Returns:
        True si les données semblent chiffrées, False sinon

    Note:
        Cette fonction n'est pas infaillible. Elle est utilisée pour
        la rétrocompatibilité avec les messages non chiffrés.
    """
    try:
        # Essayer de décoder le Base64
        decoded = base64.b64decode(data, validate=True)

        # Vérifier la longueur minimale (IV + au moins un bloc)
        if len(decoded) < 32:  # 16 (IV) + 16 (min un bloc)
            return False

        # Vérifier que c'est un multiple de 16 (taille de bloc AES)
        if len(decoded) % 16 != 0:
            return False

        return True

    except Exception:
        return False


if __name__ == "__main__":
    # Tests unitaires
    print("=" * 70)
    print("  Tests crypto_utils.py")
    print("=" * 70)
    print()

    # Test 1: Chiffrement/Déchiffrement basique
    print("Test 1: Chiffrement/Déchiffrement basique")
    plaintext = "Hello, World!"
    encrypted = encrypt(plaintext)
    decrypted = decrypt(encrypted)
    print(f"  Plaintext:  {plaintext}")
    print(f"  Encrypted:  {encrypted[:50]}...")
    print(f"  Decrypted:  {decrypted}")
    assert plaintext == decrypted, "❌ Test 1 FAILED"
    print("  ✅ Test 1 PASSED")
    print()

    # Test 2: JSON
    print("Test 2: Chiffrement JSON")
    json_data = '{"client_id":"abc123","status":"alive"}'
    encrypted_json = encrypt(json_data)
    decrypted_json = decrypt(encrypted_json)
    print(f"  Original JSON:  {json_data}")
    print(f"  Encrypted:      {encrypted_json[:50]}...")
    print(f"  Decrypted JSON: {decrypted_json}")
    assert json_data == decrypted_json, "❌ Test 2 FAILED"
    print("  ✅ Test 2 PASSED")
    print()

    # Test 3: Chaînes de différentes longueurs (padding)
    print("Test 3: Padding PKCS7 (différentes longueurs)")
    for length in [1, 15, 16, 17, 31, 32, 33, 100]:
        test_str = "A" * length
        enc = encrypt(test_str)
        dec = decrypt(enc)
        assert test_str == dec, f"❌ Test 3 FAILED pour longueur {length}"
        print(f"  Longueur {length:3d}: ✅")
    print("  ✅ Test 3 PASSED")
    print()

    # Test 4: Caractères spéciaux et UTF-8
    print("Test 4: UTF-8 et caractères spéciaux")
    special = "Héllo 世界 🔐 \n\t\r"
    enc_special = encrypt(special)
    dec_special = decrypt(enc_special)
    assert special == dec_special, "❌ Test 4 FAILED"
    print(f"  Original: {repr(special)}")
    print(f"  Decrypted: {repr(dec_special)}")
    print("  ✅ Test 4 PASSED")
    print()

    # Test 5: IV unique
    print("Test 5: IV unique pour chaque chiffrement")
    plain = "same message"
    enc1 = encrypt(plain)
    enc2 = encrypt(plain)
    assert enc1 != enc2, "❌ Test 5 FAILED - IVs identiques!"
    print(f"  Encrypted 1: {enc1[:40]}...")
    print(f"  Encrypted 2: {enc2[:40]}...")
    print("  ✅ Test 5 PASSED - IVs différents")
    print()

    print("=" * 70)
    print("  ✅ Tous les tests sont PASSÉS")
    print("=" * 70)
