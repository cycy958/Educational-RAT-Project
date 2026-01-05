"""
Module de gestion des sessions clients pour le serveur d'administration réseau.

Ce module fournit une gestion centralisée et thread-safe des clients connectés
au serveur d'administration. Il gère l'enregistrement, les heartbeats, et le
suivi de l'état de chaque client.

Classes:
    ClientInfo: Dataclass représentant les informations d'un client.
    ClientManager: Gestionnaire thread-safe des sessions clients.

Exemple d'utilisation:
    >>> from client_manager import ClientManager
    >>> manager = ClientManager()
    >>> client_id = manager.register_client("DESKTOP-ABC", "192.168.56.101", "Windows 10")
    >>> manager.update_beacon(client_id)
    >>> clients = manager.get_active_clients(timeout=30)
"""

import uuid
import time
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any

from logger import setup_logger

# Initialisation du logger
logger = setup_logger(__name__)


@dataclass
class ClientInfo:
    """
    Représente les informations d'un client connecté.

    Cette dataclass stocke toutes les métadonnées nécessaires pour suivre
    un client dans le système d'administration réseau.

    Attributes:
        client_id: UUID unique identifiant le client.
        hostname: Nom de la machine (ex: "DESKTOP-ABC").
        ip: Adresse IP du client (ex: "192.168.56.101").
        os: Système d'exploitation (ex: "Windows 10 Pro").
        first_seen: Timestamp de la première connexion (time.time()).
        last_seen: Timestamp du dernier heartbeat (time.time()).
        status: État actuel du client ("active", "inactive", "disconnected").

    Exemple:
        >>> client = ClientInfo(
        ...     client_id="550e8400-...",
        ...     hostname="DESKTOP-ABC",
        ...     ip="192.168.56.101",
        ...     os="Windows 10",
        ...     first_seen=time.time(),
        ...     last_seen=time.time()
        ... )
    """

    client_id: str
    hostname: str
    ip: str
    os: str
    first_seen: float
    last_seen: float
    status: str = "active"
    is_admin: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """
        Convertit l'objet ClientInfo en dictionnaire JSON-compatible.

        Les timestamps sont convertis au format ISO 8601 pour faciliter
        la lecture et l'interopérabilité.

        Returns:
            Dictionnaire avec toutes les informations du client.

        Exemple:
            >>> client.to_dict()
            {
                "client_id": "550e8400-...",
                "hostname": "DESKTOP-ABC",
                "ip": "192.168.56.101",
                "os": "Windows 10",
                "first_seen": "2025-11-24T14:30:00",
                "last_seen": "2025-11-24T14:35:00",
                "status": "active"
            }
        """
        return {
            "client_id": self.client_id,
            "hostname": self.hostname,
            "ip": self.ip,
            "os": self.os,
            "first_seen": datetime.fromtimestamp(self.first_seen).isoformat(),
            "last_seen": datetime.fromtimestamp(self.last_seen).isoformat(),
            "status": self.status,
            "is_admin": self.is_admin
        }

    def is_active(self, timeout: int = 30) -> bool:
        """
        Vérifie si le client est actif selon le timeout spécifié.

        Un client est considéré actif si son dernier heartbeat a été reçu
        il y a moins de `timeout` secondes.

        Args:
            timeout: Délai maximal en secondes (défaut: 30).

        Returns:
            True si le client est actif, False sinon.

        Exemple:
            >>> client.is_active(timeout=30)
            True
            >>> client.is_active(timeout=5)  # Si dernier beacon > 5s
            False
        """
        elapsed = time.time() - self.last_seen
        return elapsed < timeout

    def update_last_seen(self) -> None:
        """
        Met à jour le timestamp du dernier heartbeat.

        Utilise time.time() pour enregistrer l'instant actuel et
        met à jour le status à "active".

        Exemple:
            >>> client.update_last_seen()
            >>> print(client.last_seen)  # Timestamp actuel
            1732456789.123
        """
        self.last_seen = time.time()
        self.status = "active"


class ClientManager:
    """
    Gestionnaire thread-safe des sessions clients.

    Cette classe gère l'ensemble des clients connectés au serveur d'administration.
    Toutes les opérations sont thread-safe grâce à l'utilisation d'un verrou.

    Attributes:
        _clients: Dictionnaire des clients {client_id: ClientInfo}.
        _lock: Verrou threading pour garantir la thread-safety.

    Exemple:
        >>> manager = ClientManager()
        >>> client_id = manager.register_client("PC-WIN10", "192.168.56.101", "Windows 10")
        >>> manager.update_beacon(client_id)
        True
    """

    def __init__(self) -> None:
        """
        Initialise le gestionnaire de clients.

        Crée les structures de données internes et le verrou de synchronisation.
        """
        self._clients: Dict[str, ClientInfo] = {}
        self._aes_keys: Dict[str, bytes] = {}  # client_id -> clé AES unique
        self._lock = threading.Lock()
        logger.info("ClientManager initialisé")

    def register_client(self, hostname: str, ip: str, os: str, is_admin: bool = False) -> str:
        """
        Enregistre un nouveau client dans le système.

        Génère un UUID unique, crée un objet ClientInfo et l'enregistre
        dans le dictionnaire des clients de manière thread-safe.

        Args:
            hostname: Nom de la machine (ex: "DESKTOP-ABC").
            ip: Adresse IP du client (ex: "192.168.56.101").
            os: Système d'exploitation (ex: "Windows 10 Pro").
            is_admin: True si le client a les droits administrateur (défaut: False).

        Returns:
            UUID unique du client enregistré.

        Raises:
            ValueError: Si l'un des paramètres est vide.

        Exemple:
            >>> manager = ClientManager()
            >>> client_id = manager.register_client("PC-WIN10", "192.168.1.100", "Windows 10", is_admin=True)
            >>> print(client_id)
            "550e8400-e29b-41d4-a716-446655440000"
        """
        try:
            # Validation des paramètres
            if not all([hostname, ip, os]):
                raise ValueError("Tous les paramètres doivent être non vides")

            # Génération UUID et création client
            client_id = str(uuid.uuid4())
            timestamp = time.time()

            client = ClientInfo(
                client_id=client_id,
                hostname=hostname,
                ip=ip,
                os=os,
                first_seen=timestamp,
                last_seen=timestamp,
                status="active",
                is_admin=is_admin
            )

            # Enregistrement thread-safe
            with self._lock:
                self._clients[client_id] = client

            logger.info(
                f"Client enregistré: {hostname} ({ip}) - ID: {client_id}"
            )

            return client_id

        except ValueError as e:
            logger.error(f"Erreur de validation lors de l'enregistrement: {e}")
            raise
        except Exception as e:
            logger.error(f"Erreur lors de l'enregistrement client: {e}", exc_info=True)
            raise

    def update_beacon(self, client_id: str) -> bool:
        """
        Met à jour le timestamp du dernier heartbeat d'un client.

        Args:
            client_id: UUID du client.

        Returns:
            True si le client existe et a été mis à jour, False sinon.

        Exemple:
            >>> manager.update_beacon("550e8400-...")
            True
            >>> manager.update_beacon("client-inexistant")
            False
        """
        try:
            with self._lock:
                if client_id not in self._clients:
                    logger.warning(f"Tentative de beacon pour client inconnu: {client_id}")
                    return False

                client = self._clients[client_id]
                client.update_last_seen()

                logger.debug(
                    f"Beacon mis à jour: {client.hostname} ({client.ip}) - ID: {client_id}"
                )

                return True

        except Exception as e:
            logger.error(f"Erreur lors de la mise à jour du beacon: {e}", exc_info=True)
            return False

    def get_client(self, client_id: str) -> Optional[ClientInfo]:
        """
        Récupère les informations d'un client spécifique.

        Args:
            client_id: UUID du client.

        Returns:
            ClientInfo du client ou None si inexistant.

        Exemple:
            >>> client = manager.get_client("550e8400-...")
            >>> if client:
            ...     print(client.hostname)
            "DESKTOP-ABC"
        """
        try:
            with self._lock:
                client = self._clients.get(client_id)

                if client is None:
                    logger.debug(f"Client introuvable: {client_id}")

                return client

        except Exception as e:
            logger.error(f"Erreur lors de la récupération du client: {e}", exc_info=True)
            return None

    def get_active_clients(self, timeout: int = 30) -> List[ClientInfo]:
        """
        Récupère la liste des clients actifs.

        Un client est considéré actif si son dernier heartbeat a été reçu
        il y a moins de `timeout` secondes.

        Args:
            timeout: Délai maximal d'inactivité en secondes (défaut: 30).

        Returns:
            Liste des ClientInfo actifs.

        Exemple:
            >>> active = manager.get_active_clients(timeout=30)
            >>> print(f"{len(active)} clients actifs")
            3 clients actifs
        """
        try:
            with self._lock:
                active_clients = [
                    client for client in self._clients.values()
                    if client.is_active(timeout)
                ]

                logger.debug(
                    f"{len(active_clients)}/{len(self._clients)} clients actifs "
                    f"(timeout: {timeout}s)"
                )

                return active_clients

        except Exception as e:
            logger.error(f"Erreur lors de la récupération des clients actifs: {e}", exc_info=True)
            return []

    def get_all_clients(self) -> List[ClientInfo]:
        """
        Récupère la liste complète de tous les clients.

        Returns:
            Liste de tous les ClientInfo enregistrés.

        Exemple:
            >>> all_clients = manager.get_all_clients()
            >>> for client in all_clients:
            ...     print(client.hostname)
        """
        try:
            with self._lock:
                return list(self._clients.values())

        except Exception as e:
            logger.error(f"Erreur lors de la récupération de tous les clients: {e}", exc_info=True)
            return []

    def remove_client(self, client_id: str) -> bool:
        """
        Supprime un client du système.

        Supprime également la clé AES associée si elle existe.

        Args:
            client_id: UUID du client à supprimer.

        Returns:
            True si le client existait et a été supprimé, False sinon.

        Exemple:
            >>> manager.remove_client("550e8400-...")
            True
            >>> manager.remove_client("client-inexistant")
            False
        """
        try:
            with self._lock:
                if client_id not in self._clients:
                    logger.warning(f"Tentative de suppression client inexistant: {client_id}")
                    return False

                client = self._clients.pop(client_id)

                # Supprimer aussi la clé AES si elle existe
                if client_id in self._aes_keys:
                    del self._aes_keys[client_id]
                    logger.debug(f"Clé AES supprimée avec le client {client_id[:8]}...")

                logger.info(
                    f"Client supprimé: {client.hostname} ({client.ip}) - ID: {client_id}"
                )

                return True

        except Exception as e:
            logger.error(f"Erreur lors de la suppression du client: {e}", exc_info=True)
            return False

    def get_stats(self) -> Dict[str, int]:
        """
        Calcule les statistiques des clients.

        Returns:
            Dictionnaire avec les compteurs:
                - total: Nombre total de clients
                - active: Clients actifs (< 30s)
                - inactive: Clients inactifs (>= 30s)

        Exemple:
            >>> stats = manager.get_stats()
            >>> print(stats)
            {"total": 10, "active": 7, "inactive": 3}
        """
        try:
            with self._lock:
                total = len(self._clients)
                active = sum(1 for c in self._clients.values() if c.is_active(30))
                inactive = total - active

                stats = {
                    "total": total,
                    "active": active,
                    "inactive": inactive
                }

                logger.debug(f"Stats clients: {stats}")

                return stats

        except Exception as e:
            logger.error(f"Erreur lors du calcul des stats: {e}", exc_info=True)
            return {"total": 0, "active": 0, "inactive": 0}

    def set_aes_key(self, client_id: str, key: bytes) -> None:
        """
        Stocke la clé AES unique pour un client.

        Cette clé est générée dynamiquement via Diffie-Hellman lors de
        l'enregistrement du client.

        Args:
            client_id: UUID du client
            key: Clé AES-256 (32 bytes)

        Exemple:
            >>> manager.set_aes_key("550e8400-...", b"\\x2e\\x00\\xc1...")
        """
        try:
            with self._lock:
                self._aes_keys[client_id] = key
                logger.info(f"Clé AES définie pour client {client_id[:8]}...")

        except Exception as e:
            logger.error(f"Erreur lors de la définition de la clé AES: {e}", exc_info=True)

    def get_aes_key(self, client_id: str) -> Optional[bytes]:
        """
        Récupère la clé AES unique d'un client.

        Args:
            client_id: UUID du client

        Returns:
            Clé AES-256 (32 bytes) ou None si non trouvée

        Exemple:
            >>> key = manager.get_aes_key("550e8400-...")
            >>> if key:
            ...     print(f"Clé trouvée: {len(key)} bytes")
        """
        try:
            with self._lock:
                return self._aes_keys.get(client_id)

        except Exception as e:
            logger.error(f"Erreur lors de la récupération de la clé AES: {e}", exc_info=True)
            return None

    def remove_aes_key(self, client_id: str) -> bool:
        """
        Supprime la clé AES d'un client.

        Utilisé lors de la déconnexion d'un client pour libérer la mémoire.

        Args:
            client_id: UUID du client

        Returns:
            True si la clé existait et a été supprimée, False sinon

        Exemple:
            >>> manager.remove_aes_key("550e8400-...")
            True
        """
        try:
            with self._lock:
                if client_id in self._aes_keys:
                    del self._aes_keys[client_id]
                    logger.info(f"Clé AES supprimée pour client {client_id[:8]}...")
                    return True
                return False

        except Exception as e:
            logger.error(f"Erreur lors de la suppression de la clé AES: {e}", exc_info=True)
            return False

    def cleanup_inactive(self, timeout: int = 300) -> int:
        """
        Marque les clients inactifs comme "disconnected".

        Parcourt tous les clients et change leur status à "disconnected"
        s'ils n'ont pas envoyé de heartbeat depuis `timeout` secondes.

        Args:
            timeout: Délai d'inactivité en secondes (défaut: 300 = 5 min).

        Returns:
            Nombre de clients marqués comme déconnectés.

        Exemple:
            >>> affected = manager.cleanup_inactive(timeout=300)
            >>> print(f"{affected} clients marqués comme déconnectés")
            2 clients marqués comme déconnectés
        """
        try:
            affected = 0

            with self._lock:
                for client in self._clients.values():
                    elapsed = time.time() - client.last_seen

                    if elapsed >= timeout and client.status != "disconnected":
                        client.status = "disconnected"
                        affected += 1
                        logger.info(
                            f"Client marqué déconnecté: {client.hostname} "
                            f"(inactif depuis {int(elapsed)}s)"
                        )

            if affected > 0:
                logger.info(f"Cleanup: {affected} client(s) marqué(s) comme déconnecté(s)")

            return affected

        except Exception as e:
            logger.error(f"Erreur lors du cleanup: {e}", exc_info=True)
            return 0


# Tests et exemples d'utilisation
if __name__ == "__main__":
    """
    Tests inline du module client_manager.

    Exécutez ce script directement pour tester toutes les fonctionnalités
    du gestionnaire de clients.
    """
    print("="*70)
    print("🧪 TESTS CLIENT MANAGER - SYSTÈME D'ADMINISTRATION RÉSEAU")
    print("="*70)

    # 1. Création du manager
    print("\n[TEST 1] Création ClientManager")
    manager = ClientManager()
    print("✅ ClientManager créé")

    # 2. Enregistrement de clients de test
    print("\n[TEST 2] Enregistrement de clients")
    clients_test = [
        ("DESKTOP-WIN10", "192.168.56.101", "Windows 10 Pro"),
        ("LAPTOP-DEBIAN", "192.168.56.102", "Debian 12"),
        ("SERVER-UBUNTU", "192.168.56.103", "Ubuntu 22.04 LTS")
    ]

    client_ids = []
    for hostname, ip, os in clients_test:
        client_id = manager.register_client(hostname, ip, os)
        client_ids.append(client_id)
        print(f"✅ Client enregistré: {hostname} - ID: {client_id[:8]}...")

    # 3. Test update_beacon
    print("\n[TEST 3] Mise à jour beacons")
    for i, client_id in enumerate(client_ids):
        success = manager.update_beacon(client_id)
        print(f"✅ Beacon {i+1}/3 mis à jour: {success}")

    # Test beacon client inexistant
    fake_beacon = manager.update_beacon("fake-uuid-12345")
    print(f"❌ Beacon client inexistant (attendu False): {fake_beacon}")
    assert fake_beacon is False, "Beacon client inexistant devrait retourner False"

    # 4. Test get_client
    print("\n[TEST 4] Récupération informations client")
    test_client = manager.get_client(client_ids[0])
    if test_client:
        print(f"✅ Client récupéré: {test_client.hostname}")
        print(f"   Détails: {test_client.to_dict()}")
    else:
        print("❌ Échec récupération client")

    # 5. Test get_active_clients
    print("\n[TEST 5] Liste des clients actifs")
    active = manager.get_active_clients(timeout=30)
    print(f"✅ Clients actifs (timeout 30s): {len(active)}/{len(client_ids)}")
    for client in active:
        print(f"   - {client.hostname} ({client.ip})")

    # 6. Test get_stats
    print("\n[TEST 6] Statistiques système")
    stats = manager.get_stats()
    print(f"✅ Stats: {stats}")
    assert stats["total"] == 3, "Nombre total incorrect"
    assert stats["active"] == 3, "Nombre actifs incorrect"
    print("   Validation: OK")

    # 7. Test get_all_clients
    print("\n[TEST 7] Récupération tous les clients")
    all_clients = manager.get_all_clients()
    print(f"✅ Total clients: {len(all_clients)}")
    for client in all_clients:
        print(f"   - {client.hostname} | Status: {client.status}")

    # 8. Test simulation inactivité + cleanup
    print("\n[TEST 8] Simulation inactivité et cleanup")
    print("⏳ Simulation inactivité (modification manuelle last_seen)...")
    test_client = manager.get_client(client_ids[1])
    if test_client:
        # Simuler une inactivité de 6 minutes
        test_client.last_seen = time.time() - 360
        print(f"   Client {test_client.hostname} rendu inactif (-6 min)")

    affected = manager.cleanup_inactive(timeout=300)  # 5 min
    print(f"✅ Cleanup effectué: {affected} client(s) marqué(s) déconnecté(s)")

    # Vérification des stats après cleanup
    stats_after = manager.get_stats()
    print(f"✅ Stats après cleanup: {stats_after}")

    # 9. Test remove_client
    print("\n[TEST 9] Suppression de clients")
    removed = manager.remove_client(client_ids[2])
    print(f"✅ Client supprimé: {removed}")

    # Test suppression client inexistant
    fake_remove = manager.remove_client("fake-uuid-99999")
    print(f"❌ Suppression client inexistant (attendu False): {fake_remove}")
    assert fake_remove is False, "Suppression client inexistant devrait retourner False"

    # Stats finales
    print("\n[TEST 10] Statistiques finales")
    final_stats = manager.get_stats()
    print(f"✅ Stats finales: {final_stats}")
    assert final_stats["total"] == 2, "Nombre final incorrect après suppression"

    # 10. Test thread-safety basique
    print("\n[TEST 11] Test thread-safety basique")
    import threading

    def worker_register(manager: ClientManager, worker_id: int) -> None:
        """Thread worker pour test concurrentiel."""
        for i in range(5):
            manager.register_client(
                f"WORKER-{worker_id}-{i}",
                f"192.168.100.{worker_id * 10 + i}",
                f"TestOS-{worker_id}"
            )

    threads = []
    for i in range(3):
        t = threading.Thread(target=worker_register, args=(manager, i))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    final_count = len(manager.get_all_clients())
    print(f"✅ Test concurrentiel: {final_count} clients enregistrés (15 + 2 précédents attendus)")
    assert final_count == 17, f"Thread-safety: attendu 17, obtenu {final_count}"

    print("\n" + "="*70)
    print("✅ TOUS LES TESTS RÉUSSIS")
    print("="*70)
