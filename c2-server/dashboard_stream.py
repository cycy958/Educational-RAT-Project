"""
Module de visualisation temps réel pour le dashboard d'administration réseau.

Ce module permet aux techniciens support de voir l'écran des utilisateurs
en temps réel pour les assister à distance (comme TeamViewer ou AnyDesk).

Routes:
    - GET /stream/<client_id> : Page de visualisation du flux d'écran
    - GET /api/screenshot/<client_id> : Récupération d'un screenshot en temps réel

Exemple d'utilisation:
    1. Le technicien accède à /stream/<client_id> dans son navigateur
    2. La page rafraîchit automatiquement l'image toutes les 2 secondes
    3. L'image est récupérée via /api/screenshot/<client_id>
"""

import time
import base64
import threading
from pathlib import Path
from typing import Optional, Tuple, Dict
from datetime import datetime

from flask import Flask, Response, jsonify, render_template_string
from logger import setup_logger
from client_manager import ClientManager
from command_queue import CommandQueue

logger = setup_logger(__name__)

# Dossier pour stocker temporairement les screenshots
SCREENSHOTS_DIR = Path(__file__).parent / "screenshots"
SCREENSHOTS_DIR.mkdir(exist_ok=True)

# Cache des screenshots en mémoire {client_id: {"image": base64_data, "timestamp": timestamp}}
screenshot_cache: Dict[str, Dict[str, any]] = {}
cache_lock = threading.Lock()

# Durée de validité du cache (60 secondes)
CACHE_VALIDITY_SECONDS = 60


# Template HTML pour la page de streaming
STREAM_PAGE_HTML = """
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Visualisation Écran - {{ hostname }}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            flex-direction: column;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
        }

        .header {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 10px;
            padding: 20px 30px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 1200px;
        }

        .header h1 {
            color: #333;
            font-size: 24px;
            margin-bottom: 10px;
        }

        .client-info {
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
            font-size: 14px;
            color: #666;
        }

        .client-info span {
            display: flex;
            align-items: center;
            gap: 5px;
        }

        .status-indicator {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            display: inline-block;
        }

        .status-connected {
            background-color: #10b981;
            box-shadow: 0 0 10px rgba(16, 185, 129, 0.5);
        }

        .status-disconnected {
            background-color: #ef4444;
            box-shadow: 0 0 10px rgba(239, 68, 68, 0.5);
        }

        .controls {
            display: flex;
            gap: 10px;
            align-items: center;
        }

        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            transition: all 0.3s;
        }

        .btn-primary {
            background-color: #3b82f6;
            color: white;
        }

        .btn-primary:hover {
            background-color: #2563eb;
        }

        .btn-danger {
            background-color: #ef4444;
            color: white;
        }

        .btn-danger:hover {
            background-color: #dc2626;
        }

        .screen-container {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 1200px;
            display: flex;
            flex-direction: column;
            align-items: center;
        }

        .screen-wrapper {
            position: relative;
            width: 100%;
            display: flex;
            justify-content: center;
        }

        #screenshot {
            max-width: 100%;
            height: auto;
            border: 2px solid #e5e7eb;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }

        .loading-overlay {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: rgba(255, 255, 255, 0.9);
            padding: 20px 40px;
            border-radius: 10px;
            display: none;
        }

        .loading-overlay.active {
            display: block;
        }

        .spinner {
            border: 4px solid #f3f4f6;
            border-top: 4px solid #3b82f6;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .error-message {
            color: #ef4444;
            background: #fee2e2;
            padding: 15px;
            border-radius: 5px;
            margin-top: 20px;
            display: none;
        }

        .error-message.active {
            display: block;
        }

        .stats {
            margin-top: 15px;
            display: flex;
            gap: 20px;
            font-size: 12px;
            color: #666;
        }

        .stat-item {
            display: flex;
            align-items: center;
            gap: 5px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Visualisation Écran - Support Technique</h1>
        <div class="client-info">
            <span>
                <span id="status-indicator" class="status-indicator status-disconnected"></span>
                <strong id="connection-status">Connexion...</strong>
            </span>
            <span><strong>Client:</strong> {{ hostname }}</span>
            <span><strong>IP:</strong> {{ ip }}</span>
            <span><strong>ID:</strong> {{ client_id[:16] }}...</span>
        </div>
        <div class="controls" style="margin-top: 15px;">
            <button id="toggle-stream" class="btn btn-primary" onclick="toggleStream()">
                Démarrer le flux
            </button>
            <button id="manual-refresh" class="btn btn-primary" onclick="manualRefresh()">
                Rafraîchir maintenant
            </button>
        </div>
    </div>

    <div class="screen-container">
        <div class="screen-wrapper">
            <img id="screenshot" src="" alt="Écran du client" style="display: none;">
            <div id="loading" class="loading-overlay active">
                <div class="spinner"></div>
                <p style="text-align: center; margin-top: 10px; color: #666;">Chargement...</p>
            </div>
        </div>

        <div id="error-message" class="error-message"></div>

        <div class="stats">
            <div class="stat-item">
                <strong>Dernière mise à jour:</strong>
                <span id="last-update">Jamais</span>
            </div>
            <div class="stat-item">
                <strong>Rafraîchissements:</strong>
                <span id="refresh-count">0</span>
            </div>
            <div class="stat-item">
                <strong>Erreurs:</strong>
                <span id="error-count">0</span>
            </div>
        </div>
    </div>

    <script>
        const clientId = "{{ client_id }}";
        let streamActive = false;
        let refreshInterval = null;
        let refreshCount = 0;
        let errorCount = 0;

        const screenshotImg = document.getElementById('screenshot');
        const loadingOverlay = document.getElementById('loading');
        const errorMessage = document.getElementById('error-message');
        const statusIndicator = document.getElementById('status-indicator');
        const connectionStatus = document.getElementById('connection-status');
        const toggleBtn = document.getElementById('toggle-stream');
        const lastUpdateSpan = document.getElementById('last-update');
        const refreshCountSpan = document.getElementById('refresh-count');
        const errorCountSpan = document.getElementById('error-count');

        async function fetchScreenshot() {
            try {
                loadingOverlay.classList.add('active');
                errorMessage.classList.remove('active');

                const response = await fetch(`/api/screenshot/${clientId}`);
                const data = await response.json();

                if (response.ok && data.status === 'success') {
                    // Mettre à jour l'image
                    screenshotImg.src = `data:image/bmp;base64,${data.screenshot}`;
                    screenshotImg.style.display = 'block';

                    // Mettre à jour le statut
                    statusIndicator.className = 'status-indicator status-connected';
                    connectionStatus.textContent = 'Connecté';

                    // Mettre à jour les stats
                    const now = new Date();
                    lastUpdateSpan.textContent = now.toLocaleTimeString('fr-FR');
                    refreshCount++;
                    refreshCountSpan.textContent = refreshCount;

                    loadingOverlay.classList.remove('active');
                } else {
                    throw new Error(data.error || 'Erreur inconnue');
                }
            } catch (error) {
                console.error('Erreur lors de la récupération du screenshot:', error);

                // Afficher l'erreur
                errorMessage.textContent = `Erreur: ${error.message}`;
                errorMessage.classList.add('active');

                // Mettre à jour le statut
                statusIndicator.className = 'status-indicator status-disconnected';
                connectionStatus.textContent = 'Déconnecté';

                // Incrémenter le compteur d'erreurs
                errorCount++;
                errorCountSpan.textContent = errorCount;

                loadingOverlay.classList.remove('active');
            }
        }

        function toggleStream() {
            if (streamActive) {
                // Arrêter le flux
                clearInterval(refreshInterval);
                streamActive = false;
                toggleBtn.textContent = 'Démarrer le flux';
                toggleBtn.className = 'btn btn-primary';
                statusIndicator.className = 'status-indicator status-disconnected';
                connectionStatus.textContent = 'Flux arrêté';
            } else {
                // Démarrer le flux
                streamActive = true;
                toggleBtn.textContent = 'Arrêter le flux';
                toggleBtn.className = 'btn btn-danger';

                // Premier fetch immédiat
                fetchScreenshot();

                // Configurer le rafraîchissement automatique (toutes les 2 secondes)
                refreshInterval = setInterval(fetchScreenshot, 2000);
            }
        }

        function manualRefresh() {
            fetchScreenshot();
        }

        // Démarrer automatiquement le flux au chargement de la page
        window.addEventListener('load', () => {
            setTimeout(() => {
                toggleStream();
            }, 500);
        });
    </script>
</body>
</html>
"""


def register_dashboard_routes(app: Flask, client_manager: ClientManager, command_queue: CommandQueue) -> None:
    """
    Enregistre les routes du dashboard dans l'application Flask.

    Args:
        app: Instance Flask
        client_manager: Gestionnaire de clients
        command_queue: Gestionnaire de file d'attente des commandes
    """

    @app.route('/stream/<client_id>', methods=['GET'])
    def stream_view(client_id: str) -> Tuple[str, int] | Tuple[Response, int]:
        """
        Page de visualisation du flux d'écran d'un client.

        Affiche une page HTML avec JavaScript qui rafraîchit l'image
        toutes les 2 secondes en récupérant /api/screenshot/<client_id>.

        Args:
            client_id: UUID du client à visualiser

        Returns:
            Page HTML ou erreur 404 si client inconnu
        """
        try:
            # Vérifier que le client existe
            client = client_manager.get_client(client_id)

            if not client:
                logger.warning(f"Tentative d'accès au stream d'un client inconnu: {client_id}")
                return jsonify({"error": "Client non trouvé"}), 404

            logger.info(f"Ouverture du stream pour {client.hostname} ({client_id[:8]}...)")

            # Rendre la page HTML avec les informations du client
            html = render_template_string(
                STREAM_PAGE_HTML,
                client_id=client_id,
                hostname=client.hostname,
                ip=client.ip
            )

            return html, 200

        except Exception as e:
            logger.error(f"Erreur lors de l'accès au stream: {e}", exc_info=True)
            return jsonify({"error": "Erreur interne du serveur"}), 500


    @app.route('/api/screenshot/<client_id>', methods=['GET'])
    def get_screenshot(client_id: str) -> Tuple[Response, int]:
        """
        API pour récupérer un screenshot d'un client en temps réel.

        Stratégie de cache intelligente:
        1. Vérifier si un screenshot récent existe en cache (< 60 secondes)
        2. Si oui, retourner immédiatement
        3. Sinon, envoyer une commande et attendre (timeout 10 secondes)
        4. Si timeout, retourner le dernier screenshot du cache s'il existe

        Args:
            client_id: UUID du client

        Returns:
            JSON avec screenshot en base64 ou erreur
        """
        try:
            # Vérifier que le client existe
            client = client_manager.get_client(client_id)

            if not client:
                logger.warning(f"Screenshot demandé pour client inconnu: {client_id}")
                return jsonify({
                    "status": "error",
                    "error": "Client non trouvé"
                }), 404

            # 1. Vérifier si un screenshot récent existe en cache
            current_time = time.time()
            cached_screenshot = None
            cache_age = None

            with cache_lock:
                if client_id in screenshot_cache:
                    cached_data = screenshot_cache[client_id]
                    cache_age = current_time - cached_data["timestamp"]

                    # Si le cache est récent (< 60 secondes), le retourner immédiatement
                    if cache_age < CACHE_VALIDITY_SECONDS:
                        logger.debug(f"Screenshot servi depuis le cache pour {client.hostname} (age: {cache_age:.1f}s)")
                        return jsonify({
                            "status": "success",
                            "screenshot": cached_data["image"],
                            "timestamp": datetime.fromtimestamp(cached_data["timestamp"]).isoformat(),
                            "client_id": client_id,
                            "cached": True,
                            "cache_age": round(cache_age, 1)
                        }), 200

                    # Sauvegarder le screenshot du cache comme fallback
                    cached_screenshot = cached_data["image"]

            # 2. Le cache est périmé ou n'existe pas, demander un nouveau screenshot
            task_id = command_queue.add_task(
                client_id=client_id,
                task_type="screenshot",
                params={}
            )

            logger.debug(f"Commande screenshot envoyée à {client.hostname} (task: {task_id[:8]}...)")

            # 3. Attendre le résultat avec timeout de 10 secondes
            timeout = 10.0
            start_time = time.time()
            result = None

            while time.time() - start_time < timeout:
                result = command_queue.get_result(task_id)

                if result:
                    break

                # Attendre 100ms avant de revérifier
                time.sleep(0.1)

            # 4. Si timeout, retourner le dernier screenshot du cache s'il existe
            if not result:
                logger.warning(f"Timeout lors de l'attente du screenshot (task: {task_id[:8]}...)")

                # Fallback: retourner le screenshot du cache (même périmé)
                if cached_screenshot:
                    logger.info(f"Fallback: retour du screenshot du cache périmé (age: {cache_age:.1f}s)")
                    return jsonify({
                        "status": "success",
                        "screenshot": cached_screenshot,
                        "timestamp": datetime.fromtimestamp(screenshot_cache[client_id]["timestamp"]).isoformat(),
                        "client_id": client_id,
                        "cached": True,
                        "cache_age": round(cache_age, 1),
                        "warning": "Screenshot du cache (client n'a pas répondu)"
                    }), 200
                else:
                    # Pas de cache disponible
                    return jsonify({
                        "status": "error",
                        "error": "Timeout: le client n'a pas répondu dans les 10 secondes"
                    }), 408

            # 5. Vérifier le statut du résultat
            if result.status != "success":
                logger.error(f"Erreur screenshot: {result.error_message}")

                # Fallback: retourner le screenshot du cache en cas d'erreur
                if cached_screenshot:
                    logger.info(f"Fallback: retour du screenshot du cache après erreur")
                    return jsonify({
                        "status": "success",
                        "screenshot": cached_screenshot,
                        "timestamp": datetime.fromtimestamp(screenshot_cache[client_id]["timestamp"]).isoformat(),
                        "client_id": client_id,
                        "cached": True,
                        "cache_age": round(cache_age, 1),
                        "warning": f"Erreur lors de la capture: {result.error_message}"
                    }), 200
                else:
                    return jsonify({
                        "status": "error",
                        "error": result.error_message or "Erreur lors de la capture d'écran"
                    }), 500

            # 6. Extraire et retourner les données Base64
            output = result.output
            base64_data = None

            # Format direct: "[SCREENSHOT]base64data"
            if output.startswith("[SCREENSHOT]"):
                base64_data = output[len("[SCREENSHOT]:"):]

            # Format de sauvegarde: "[SCREENSHOT SAVED] filename"
            elif output.startswith("[SCREENSHOT SAVED]"):
                parts = output.split(" ")
                if len(parts) >= 3:
                    filename = parts[2]
                    uploads_dir = Path(__file__).parent / "uploads"
                    filepath = uploads_dir / filename

                    if filepath.exists():
                        with open(filepath, "rb") as f:
                            image_data = f.read()
                            base64_data = base64.b64encode(image_data).decode('utf-8')

            # 7. Mettre à jour le cache et retourner
            if base64_data:
                with cache_lock:
                    screenshot_cache[client_id] = {
                        "image": base64_data,
                        "timestamp": time.time()
                    }

                logger.info(f"Screenshot récupéré et mis en cache pour {client.hostname} ({len(base64_data)} chars)")

                return jsonify({
                    "status": "success",
                    "screenshot": base64_data,
                    "timestamp": datetime.now().isoformat(),
                    "client_id": client_id,
                    "cached": False
                }), 200
            else:
                logger.error(f"Format de résultat screenshot invalide: {output[:100]}")

                # Fallback final
                if cached_screenshot:
                    return jsonify({
                        "status": "success",
                        "screenshot": cached_screenshot,
                        "timestamp": datetime.fromtimestamp(screenshot_cache[client_id]["timestamp"]).isoformat(),
                        "client_id": client_id,
                        "cached": True,
                        "cache_age": round(cache_age, 1),
                        "warning": "Format invalide, screenshot du cache"
                    }), 200
                else:
                    return jsonify({
                        "status": "error",
                        "error": "Format de résultat invalide"
                    }), 500

        except Exception as e:
            logger.error(f"Erreur lors de la récupération du screenshot: {e}", exc_info=True)
            return jsonify({
                "status": "error",
                "error": "Erreur interne du serveur"
            }), 500


    logger.info("Routes du dashboard enregistrées: /stream/<client_id>, /api/screenshot/<client_id>")


if __name__ == '__main__':
    """
    Test du module dashboard_stream.

    Ce module est conçu pour être importé par server.py.
    Pour tester individuellement, décommenter le code ci-dessous.
    """
    print("="*70)
    print("Module dashboard_stream.py chargé")
    print("="*70)
    print("Routes disponibles:")
    print("  - GET /stream/<client_id> : Page de visualisation")
    print("  - GET /api/screenshot/<client_id> : API screenshot")
    print("="*70)
