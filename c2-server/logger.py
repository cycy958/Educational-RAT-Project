"""
Module de logging pour le serveur d'administration réseau.

Ce module fournit une configuration de logging robuste avec sortie console
colorisée et rotation automatique des fichiers de logs.

Exemple d'utilisation:
    >>> from logger import setup_logger
    >>> logger = setup_logger(__name__)
    >>> logger.info("Serveur HTTP démarré sur le port 8080")
    >>> logger.error("Échec de connexion client", exc_info=True)
"""

import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False


class ColoredFormatter(logging.Formatter):
    """
    Formateur de logs avec colorisation selon le niveau.

    Utilise colorama pour ajouter des couleurs aux messages de logs
    affichés dans la console.
    """

    COLORS = {
        logging.DEBUG: Fore.CYAN,
        logging.INFO: Fore.GREEN,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.RED + Style.BRIGHT,
    }

    def __init__(self, fmt: str, use_color: bool = True) -> None:
        """
        Initialise le formateur.

        Args:
            fmt: Format du message de log.
            use_color: Active la colorisation (True par défaut).
        """
        super().__init__(fmt)
        self.use_color = use_color and COLORAMA_AVAILABLE

    def format(self, record: logging.LogRecord) -> str:
        """
        Formate un enregistrement de log avec colorisation.

        Args:
            record: Enregistrement de log à formater.

        Returns:
            Message de log formaté et colorisé.
        """
        if self.use_color:
            levelname = record.levelname
            color = self.COLORS.get(record.levelno, "")
            record.levelname = f"{color}{levelname}{Style.RESET_ALL}"

        return super().format(record)


def setup_logger(
    name: str,
    log_file: str = "c2_server.log",
    level: int = logging.INFO,
    max_bytes: int = 10 * 1024 * 1024,  # 10 MB
    backup_count: int = 3,
    console_output: bool = True
) -> logging.Logger:
    """
    Configure et retourne un logger avec sortie console et fichier.

    Cette fonction crée un logger avec:
    - Sortie console colorisée (si colorama disponible)
    - Sortie fichier avec rotation automatique
    - Format standardisé: [YYYY-MM-DD HH:MM:SS] [LEVEL] [SOURCE] Message

    Args:
        name: Nom du logger (généralement __name__ du module).
        log_file: Chemin du fichier de log (défaut: "c2_server.log").
        level: Niveau de logging (défaut: logging.INFO).
        max_bytes: Taille maximale du fichier avant rotation (défaut: 10 MB).
        backup_count: Nombre de fichiers de backup à conserver (défaut: 3).
        console_output: Active la sortie console (défaut: True).

    Returns:
        Instance de logging.Logger configurée.

    Raises:
        OSError: Si impossible de créer ou écrire dans le fichier de log.

    Exemple:
        >>> logger = setup_logger(__name__)
        >>> logger.info("Serveur démarré")
        [2025-11-24 14:30:00] [INFO] [__main__] Serveur démarré
    """
    # Création du logger
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Éviter les handlers en doublon si le logger existe déjà
    if logger.handlers:
        return logger

    # Format des logs
    log_format = "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"

    # Handler console avec colorisation
    if console_output:
        try:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(level)
            console_formatter = ColoredFormatter(
                log_format,
                use_color=True
            )
            console_formatter.datefmt = date_format
            console_handler.setFormatter(console_formatter)
            logger.addHandler(console_handler)
        except Exception as e:
            print(f"Avertissement: Impossible de configurer la sortie console: {e}", file=sys.stderr)

    # Handler fichier avec rotation
    try:
        # Créer le répertoire parent si nécessaire
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        # Vérifier les permissions d'écriture
        if log_path.exists() and not os.access(log_path, os.W_OK):
            raise PermissionError(f"Pas de permission d'écriture pour {log_file}")

        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8"
        )
        file_handler.setLevel(level)
        file_formatter = logging.Formatter(log_format, datefmt=date_format)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    except PermissionError as e:
        logger.error(f"Permission refusée pour le fichier de log: {e}")
        raise
    except OSError as e:
        logger.error(f"Erreur lors de la création du fichier de log: {e}")
        raise
    except Exception as e:
        logger.error(f"Erreur inattendue lors de la configuration du logging fichier: {e}")
        raise

    return logger


# Exemple d'utilisation et tests
if __name__ == "__main__":
    """
    Exemple d'utilisation du module de logging.

    Exécutez ce script directement pour tester les différents niveaux de logs.
    """
    # Configuration du logger principal
    logger = setup_logger(__name__, log_file="test_server.log", level=logging.DEBUG)

    # Tests des différents niveaux
    logger.debug("Message de débogage - détails techniques")
    logger.info("Serveur HTTP démarré sur le port 8080")
    logger.warning("Connexion client lente détectée (>5s)")
    logger.error("Échec d'authentification du client 192.168.1.100")
    logger.critical("Serveur surchargé - mémoire à 95%")

    # Test avec exception
    try:
        result = 10 / 0
    except ZeroDivisionError:
        logger.error("Erreur de calcul détectée", exc_info=True)

    print(f"\n✅ Logs enregistrés dans 'test_server.log'")
    print(f"✅ Console colorisée: {'Activée' if COLORAMA_AVAILABLE else 'Désactivée (colorama non installé)'}")
