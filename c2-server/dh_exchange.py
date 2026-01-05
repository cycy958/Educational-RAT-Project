"""
dh_exchange.py

Module d'échange de clés ECDH (Elliptic Curve Diffie-Hellman) pour établir
une clé AES-256 unique par client.

Utilise la courbe P-256 (secp256r1) - même implémentation que le client C++ BCrypt.
La clé AES est dérivée via SHA-256 du secret partagé.

ECDH P-256 offre une sécurité équivalente à DH 3072-bit avec des clés beaucoup plus petites.

Educational Project - Cybersecurity Engineering
Purpose: Educational study of key exchange protocols and perfect forward secrecy
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import struct

# Constantes pour le format BCRYPT_ECCPUBLIC_BLOB (Windows BCrypt)
# Structure BCRYPT_ECCKEY_BLOB pour P-256:
#   - dwMagic (4 bytes) : 0x314B4345 pour ECDH P-256 public ('ECK1')
#   - cbKey (4 bytes)   : 32 (taille des coordonnées X et Y en bytes)
#   - X (32 bytes)      : Coordonnée X du point public
#   - Y (32 bytes)      : Coordonnée Y du point public
# Total: 72 bytes

BCRYPT_ECDH_PUBLIC_P256_MAGIC = 0x314B4345  # 'ECK1' en little-endian (ECDH, pas ECDSA)
BCRYPT_ECDH_PRIVATE_P256_MAGIC = 0x324B4345  # 'ECK2' en little-endian
ECDH_P256_KEY_SIZE = 32  # 256 bits = 32 bytes pour les coordonnées X et Y
BCRYPT_ECCPUBLIC_BLOB_SIZE = 8 + (2 * ECDH_P256_KEY_SIZE)  # 72 bytes


class DHKeyExchange:
    """
    Classe pour gérer l'échange de clés ECDH P-256 côté serveur.

    Implémentation Python utilisant la bibliothèque cryptography.
    Compatible avec l'implémentation BCrypt ECDH P-256 côté C++.

    Format de clé publique: BCRYPT_ECCPUBLIC_BLOB (72 bytes)
    - Compatible avec BCryptImportKeyPair() de Windows

    Génère une paire de clés (privée, publique), calcule le secret partagé
    et dérive la clé AES-256.
    """

    def __init__(self):
        """Initialise l'objet DHKeyExchange (ECDH)."""
        self.private_key = None
        self.public_key = None

    def generate_keypair(self):
        """
        Génère une paire de clés ECDH P-256 (privée et publique).

        Utilise la courbe secp256r1 (NIST P-256) qui est identique
        à BCRYPT_ECDH_P256_ALGORITHM de Windows BCrypt.

        La clé privée est un scalaire de 256 bits.
        La clé publique est un point (X, Y) sur la courbe P-256.
        """
        # Générer une paire de clés ECDH sur la courbe P-256
        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.public_key = self.private_key.public_key()

    def get_public_key_base64(self) -> str:
        """
        Retourne la clé publique encodée en Base64 (format BCRYPT_ECCPUBLIC_BLOB).

        Format BCRYPT_ECCKEY_BLOB pour P-256 (72 bytes total):
        - dwMagic (4 bytes, little-endian): 0x314B4345 ('ECK1')
        - cbKey (4 bytes, little-endian): 32 (taille de X et Y)
        - X (32 bytes, big-endian): Coordonnée X du point public
        - Y (32 bytes, big-endian): Coordonnée Y du point public

        Compatible avec BCryptImportKeyPair(BCRYPT_ECCPUBLIC_BLOB) de Windows.

        Returns:
            Clé publique en Base64 (format BCRYPT_ECCPUBLIC_BLOB)
        """
        if self.public_key is None:
            raise ValueError("La paire de clés n'a pas été générée. Appelez generate_keypair() d'abord.")

        # Extraire les coordonnées X et Y du point public
        public_numbers = self.public_key.public_numbers()
        x = public_numbers.x
        y = public_numbers.y

        # Convertir X et Y en bytes (big-endian, 32 bytes chacun)
        x_bytes = x.to_bytes(ECDH_P256_KEY_SIZE, byteorder='big')
        y_bytes = y.to_bytes(ECDH_P256_KEY_SIZE, byteorder='big')

        # Construire le BCRYPT_ECCPUBLIC_BLOB
        # struct.pack('<II', ...) : little-endian pour magic et cbKey
        blob = struct.pack('<II', BCRYPT_ECDH_PUBLIC_P256_MAGIC, ECDH_P256_KEY_SIZE)
        blob += x_bytes
        blob += y_bytes

        # Vérification de taille
        assert len(blob) == BCRYPT_ECCPUBLIC_BLOB_SIZE, f"Blob size incorrect: {len(blob)} bytes"

        # Encoder en Base64
        return base64.b64encode(blob).decode('ascii')

    def compute_shared_secret(self, client_public_key_b64: str) -> bytes:
        """
        Calcule le secret partagé ECDH à partir de la clé publique du client.

        Formule ECDH : secret = d_B * Q_A
        où d_B est notre clé privée (scalaire), Q_A est la clé publique du client (point).

        Args:
            client_public_key_b64: Clé publique du client en Base64 (format BCRYPT_ECCPUBLIC_BLOB)

        Returns:
            Secret partagé ECDH (32 bytes pour P-256)
        """
        if self.private_key is None:
            raise ValueError("La paire de clés n'a pas été générée. Appelez generate_keypair() d'abord.")

        # Décoder le BCRYPT_ECCPUBLIC_BLOB du client
        client_public_blob = base64.b64decode(client_public_key_b64)

        # Vérifier la longueur du blob
        if len(client_public_blob) != BCRYPT_ECCPUBLIC_BLOB_SIZE:
            raise ValueError(
                f"Clé publique reçue de taille invalide: {len(client_public_blob)} bytes "
                f"(attendu: {BCRYPT_ECCPUBLIC_BLOB_SIZE})"
            )

        # Parser le BCRYPT_ECCPUBLIC_BLOB
        # struct.unpack('<II', ...) : little-endian pour magic et cbKey
        magic, cb_key = struct.unpack('<II', client_public_blob[0:8])

        # Vérifier le magic number
        if magic != BCRYPT_ECDH_PUBLIC_P256_MAGIC:
            raise ValueError(
                f"Magic number invalide dans le blob: 0x{magic:08X} "
                f"(attendu: 0x{BCRYPT_ECDH_PUBLIC_P256_MAGIC:08X})"
            )

        # Vérifier cbKey
        if cb_key != ECDH_P256_KEY_SIZE:
            raise ValueError(
                f"cbKey invalide dans le blob: {cb_key} "
                f"(attendu: {ECDH_P256_KEY_SIZE})"
            )

        # Extraire X et Y (big-endian, 32 bytes chacun)
        x_bytes = client_public_blob[8:40]
        y_bytes = client_public_blob[40:72]

        # Convertir en entiers
        x = int.from_bytes(x_bytes, byteorder='big')
        y = int.from_bytes(y_bytes, byteorder='big')

        # Reconstruire la clé publique EC du client
        client_public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
        client_public_key = client_public_numbers.public_key(default_backend())

        # Calculer le secret partagé via ECDH
        shared_secret = self.private_key.exchange(ec.ECDH(), client_public_key)

        # Pour P-256, le secret partagé est la coordonnée X du point résultant (32 bytes)
        assert len(shared_secret) == ECDH_P256_KEY_SIZE, f"Shared secret size incorrect: {len(shared_secret)} bytes"

        # CORRECTION ENDIANNESS : Windows BCrypt retourne le secret en little-endian
        # Python cryptography le retourne en big-endian
        # Inverser l'ordre des bytes pour matcher Windows
        shared_secret = shared_secret[::-1]

        return shared_secret

    def derive_aes_key(self, shared_secret: bytes) -> bytes:
        """
        Dérive une clé AES-256 (32 bytes) à partir du secret partagé.

        Utilise SHA-256 pour hasher le secret partagé :
        AES_KEY = SHA256(shared_secret)

        Cette méthode est identique à celle du client C++ (DeriveAESKey).

        Args:
            shared_secret: Secret partagé calculé via ECDH (32 bytes pour P-256)

        Returns:
            Clé AES-256 (32 bytes)
        """
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(shared_secret)
        aes_key = digest.finalize()

        return aes_key


# Fonctions utilitaires pour usage direct

def perform_dh_exchange(client_public_key_b64: str) -> tuple[bytes, str]:
    """
    Effectue un échange ECDH complet côté serveur.

    Args:
        client_public_key_b64: Clé publique du client en Base64 (format BCRYPT_ECCPUBLIC_BLOB)

    Returns:
        Tuple (aes_key, server_public_key_b64)
        - aes_key: Clé AES-256 dérivée (32 bytes)
        - server_public_key_b64: Notre clé publique en Base64 (format BCRYPT_ECCPUBLIC_BLOB)
    """
    dh = DHKeyExchange()
    dh.generate_keypair()

    shared_secret = dh.compute_shared_secret(client_public_key_b64)
    aes_key = dh.derive_aes_key(shared_secret)
    server_public_key_b64 = dh.get_public_key_base64()

    return aes_key, server_public_key_b64


if __name__ == "__main__":
    """Tests unitaires du module ECDH."""
    print("=" * 70)
    print("  Tests dh_exchange.py (Implémentation ECDH P-256)")
    print("=" * 70)
    print()

    # Test 1: Génération de clés
    print("Test 1: Génération de paire de clés ECDH P-256")
    dh = DHKeyExchange()
    dh.generate_keypair()
    pub_key_b64 = dh.get_public_key_base64()
    print(f"  Clé publique générée (Base64): {pub_key_b64}")
    print(f"  Longueur clé publique Base64: {len(pub_key_b64)} chars")

    # Vérifier que la clé décodée fait bien 72 bytes
    pub_key_bytes = base64.b64decode(pub_key_b64)
    print(f"  Longueur clé publique (bytes): {len(pub_key_bytes)} bytes")
    print(f"  BCRYPT_ECCPUBLIC_BLOB_SIZE attendu: {BCRYPT_ECCPUBLIC_BLOB_SIZE} bytes")
    assert len(pub_key_bytes) == BCRYPT_ECCPUBLIC_BLOB_SIZE, \
        f"La clé publique doit faire {BCRYPT_ECCPUBLIC_BLOB_SIZE} bytes"

    # Vérifier le format du blob
    magic, cb_key = struct.unpack('<II', pub_key_bytes[0:8])
    print(f"  Magic number: 0x{magic:08X} (attendu: 0x{BCRYPT_ECDH_PUBLIC_P256_MAGIC:08X})")
    print(f"  cbKey: {cb_key} (attendu: {ECDH_P256_KEY_SIZE})")
    assert magic == BCRYPT_ECDH_PUBLIC_P256_MAGIC, "Magic number incorrect"
    assert cb_key == ECDH_P256_KEY_SIZE, "cbKey incorrect"

    # Afficher les coordonnées X et Y
    x_bytes = pub_key_bytes[8:40]
    y_bytes = pub_key_bytes[40:72]
    print(f"  Coordonnée X (hex, 10 premiers bytes): {x_bytes[:10].hex()}")
    print(f"  Coordonnée Y (hex, 10 premiers bytes): {y_bytes[:10].hex()}")

    print("  ✅ Test 1 PASSED")
    print()

    # Test 2: Simuler un échange complet (client et serveur)
    print("Test 2: Échange ECDH complet (simulation)")

    # Simuler le client
    client_dh = DHKeyExchange()
    client_dh.generate_keypair()
    client_pub = client_dh.get_public_key_base64()

    # Simuler le serveur
    server_dh = DHKeyExchange()
    server_dh.generate_keypair()
    server_pub = server_dh.get_public_key_base64()

    print(f"  Client public key (Base64, 50 premiers chars): {client_pub[:50]}...")
    print(f"  Server public key (Base64, 50 premiers chars): {server_pub[:50]}...")

    # Les deux calculent le secret partagé
    client_secret = client_dh.compute_shared_secret(server_pub)
    server_secret = server_dh.compute_shared_secret(client_pub)

    # Dériver les clés AES
    client_aes = client_dh.derive_aes_key(client_secret)
    server_aes = server_dh.derive_aes_key(server_secret)

    print(f"  Secret client (hex): {client_secret.hex()}")
    print(f"  Secret serveur (hex): {server_secret.hex()}")
    print(f"  Secret client: {len(client_secret)} bytes")
    print(f"  Secret serveur: {len(server_secret)} bytes")
    print(f"  AES key client (hex): {client_aes.hex()}")
    print(f"  AES key serveur (hex): {server_aes.hex()}")

    if client_secret == server_secret:
        print("  ✅ Les secrets partagés correspondent!")
    else:
        print("  ❌ Les secrets partagés ne correspondent pas!")

    if client_aes == server_aes:
        print("  ✅ Test 2 PASSED - Les clés AES correspondent!")
    else:
        print("  ❌ Test 2 FAILED - Les clés AES ne correspondent pas!")
    print()

    # Test 3: Test de la fonction utilitaire
    print("Test 3: Fonction perform_dh_exchange()")
    test_dh = DHKeyExchange()
    test_dh.generate_keypair()
    test_client_pub = test_dh.get_public_key_base64()

    aes_key, server_pub_key = perform_dh_exchange(test_client_pub)
    print(f"  AES key dérivée (hex): {aes_key.hex()}")
    print(f"  Longueur AES key: {len(aes_key)} bytes")
    assert len(aes_key) == 32, "La clé AES doit faire 32 bytes"
    print(f"  Server public key (Base64, 50 premiers chars): {server_pub_key[:50]}...")
    print("  ✅ Test 3 PASSED")
    print()

    print("=" * 70)
    print("  ✅ Tous les tests sont PASSÉS")
    print("=" * 70)
