#!/usr/bin/env python3
"""
CT Monitoring VPS - VERSION AMÉLIORÉE
1. Découvrir sous-domaines via CT Logs (28)
2. Check status code HTTP/HTTPS (avec suivi redirections)
3. Envoyer TOUS résultats à Discord
4. Parser et extraire NON-200 seulement
5. Stocker en DB SQLite (pool de connexions)
6. Cron job (5min) - Recheck + alerte si 200
"""

import requests
import json
import time
import os
import threading
import base64
import sqlite3
import hashlib
import urllib3
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import OrderedDict

# Supprimer les warnings SSL (verify=False intentionnel)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

print("=" * 80)
print("CT MONITORING - VERSION AMÉLIORÉE")
print(f"Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
print("=" * 80)

# ==================== CONFIGURATION ====================
DISCORD_WEBHOOK    = os.environ.get('DISCORD_WEBHOOK', '')
DOMAINS_FILE       = '/app/domains.txt'
DATA_DIR           = '/app/data'
DATABASE_FILE      = f'{DATA_DIR}/ct_monitoring.db'
POSITIONS_FILE     = f'{DATA_DIR}/ct_positions.json'
SUBDOMAINS_FILE    = f'{DATA_DIR}/subdomains.txt'
PATHS_FILE         = f'{DATA_DIR}/paths.txt'

os.makedirs(DATA_DIR, exist_ok=True)

# PARAMETRES
CHECK_INTERVAL              = 30
BATCH_SIZE                  = 500
MAX_BATCHES_CRITICAL        = 200
MAX_BATCHES_HIGH            = 100
MAX_BATCHES_MEDIUM          = 50
PARALLEL_LOGS               = 28
CACHE_MAX_SIZE              = 500000
TIMEOUT_PER_LOG             = 300
HTTP_CHECK_TIMEOUT          = 5
UNREACHABLE_RECHECK_INTERVAL = 300  # 5 minutes

# CT LOGS (28 actifs)
CT_LOGS = [
    {"name": "Google Argon2026h1",     "url": "https://ct.googleapis.com/logs/us1/argon2026h1",  "enabled": True, "priority": "CRITICAL"},
    {"name": "Google Argon2026h2",     "url": "https://ct.googleapis.com/logs/us1/argon2026h2",  "enabled": True, "priority": "CRITICAL"},
    {"name": "Google Argon2027h1",     "url": "https://ct.googleapis.com/logs/us1/argon2027h1",  "enabled": True, "priority": "HIGH"},
    {"name": "Google Xenon2026h1",     "url": "https://ct.googleapis.com/logs/eu1/xenon2026h1",  "enabled": True, "priority": "CRITICAL"},
    {"name": "Google Xenon2026h2",     "url": "https://ct.googleapis.com/logs/eu1/xenon2026h2",  "enabled": True, "priority": "CRITICAL"},
    {"name": "Google Xenon2027h1",     "url": "https://ct.googleapis.com/logs/eu1/xenon2027h1",  "enabled": True, "priority": "HIGH"},
    {"name": "Google Solera2026h1",    "url": "https://ct.googleapis.com/logs/eu1/solera2026h1", "enabled": True, "priority": "MEDIUM"},
    {"name": "Cloudflare Nimbus2026",  "url": "https://ct.cloudflare.com/logs/nimbus2026",       "enabled": True, "priority": "CRITICAL"},
    {"name": "Cloudflare Nimbus2027",  "url": "https://ct.cloudflare.com/logs/nimbus2027",       "enabled": True, "priority": "HIGH"},
    {"name": "DigiCert Wyvern2026h1",  "url": "https://wyvern.ct.digicert.com/2026h1",           "enabled": True, "priority": "HIGH"},
    {"name": "DigiCert Wyvern2027h1",  "url": "https://wyvern.ct.digicert.com/2027h1",           "enabled": True, "priority": "HIGH"},
    {"name": "DigiCert Wyvern2027h2",  "url": "https://wyvern.ct.digicert.com/2027h2",           "enabled": True, "priority": "MEDIUM"},
    {"name": "DigiCert Sphinx2026h1",  "url": "https://sphinx.ct.digicert.com/2026h1",           "enabled": True, "priority": "HIGH"},
    {"name": "DigiCert Sphinx2027h1",  "url": "https://sphinx.ct.digicert.com/2027h1",           "enabled": True, "priority": "HIGH"},
    {"name": "DigiCert Sphinx2027h2",  "url": "https://sphinx.ct.digicert.com/2027h2",           "enabled": True, "priority": "MEDIUM"},
    {"name": "Sectigo Sabre2026h1",    "url": "https://sabre2026h1.ct.sectigo.com",              "enabled": True, "priority": "HIGH"},
    {"name": "Sectigo Sabre2026h2",    "url": "https://sabre2026h2.ct.sectigo.com",              "enabled": True, "priority": "MEDIUM"},
    {"name": "Sectigo Mammoth2026h1",  "url": "https://mammoth2026h1.ct.sectigo.com",            "enabled": True, "priority": "MEDIUM"},
    {"name": "Sectigo Mammoth2026h2",  "url": "https://mammoth2026h2.ct.sectigo.com",            "enabled": True, "priority": "MEDIUM"},
    {"name": "Sectigo Tiger2026h1",    "url": "https://tiger2026h1.ct.sectigo.com",              "enabled": True, "priority": "MEDIUM"},
    {"name": "Sectigo Tiger2026h2",    "url": "https://tiger2026h2.ct.sectigo.com",              "enabled": True, "priority": "MEDIUM"},
    {"name": "Sectigo Elephant2026h1", "url": "https://elephant2026h1.ct.sectigo.com",           "enabled": True, "priority": "MEDIUM"},
    {"name": "Sectigo Elephant2026h2", "url": "https://elephant2026h2.ct.sectigo.com",           "enabled": True, "priority": "MEDIUM"},
    {"name": "LE Oak2026h1",           "url": "https://oak.ct.letsencrypt.org/2026h1",           "enabled": True, "priority": "HIGH"},
    {"name": "LE Oak2026h2",           "url": "https://oak.ct.letsencrypt.org/2026h2",           "enabled": True, "priority": "HIGH"},
    {"name": "TrustAsia Log2026a",     "url": "https://ct2026-a.trustasia.com/log2026a",         "enabled": True, "priority": "CRITICAL"},
    {"name": "TrustAsia Log2026b",     "url": "https://ct2026-b.trustasia.com/log2026b",         "enabled": True, "priority": "CRITICAL"},
    {"name": "TrustAsia HETU2027",     "url": "https://hetu2027.trustasia.com/hetu2027",         "enabled": True, "priority": "HIGH"},
]

ENABLED_LOGS    = [log for log in CT_LOGS if log['enabled']]
NB_LOGS_ACTIFS  = len(ENABLED_LOGS)

# ==================== STATS ====================
stats = {
    'certificats_analysés':  0,
    'alertes_envoyées':      0,
    'dernière_alerte':       None,
    'démarrage':             datetime.utcnow(),
    'dernière_vérification': None,
    'positions':             {},
    'logs_actifs':           NB_LOGS_ACTIFS,
    'duplicates_évités':     0,
    'parse_errors':          0,
    'matches_trouvés':       0,
    'http_checks':           0,
    'batches_processed':     0,
    'x509_count':            0,
    'precert_count':         0,
}
stats_lock = threading.Lock()

# ==================== CACHE LRU ====================
class LRUCache:
    """Cache LRU thread-safe pour éviter de retraiter les certificats déjà vus."""

    def __init__(self, max_size):
        self.cache    = OrderedDict()
        self.max_size = max_size
        self.lock     = threading.Lock()

    def contains(self, key):
        with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)
                return True
            return False

    def add(self, key):
        with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)
                return
            self.cache[key] = True
            if len(self.cache) > self.max_size:
                self.cache.popitem(last=False)

seen_certificates = LRUCache(CACHE_MAX_SIZE)

# ==================== DATABASE ====================
class CertificateDatabase:
    """
    Gestion SQLite avec connexion persistante par thread.
    Stocke SEULEMENT les domaines non-200 (inaccessibles ou erreur serveur).
    """

    def __init__(self, db_path):
        self.db_path  = db_path
        self._local   = threading.local()  # connexion par thread
        self.init_db()

    def _get_conn(self):
        """Retourne la connexion SQLite du thread courant (créée si absente)."""
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._local.conn.execute('PRAGMA journal_mode=WAL')   # lectures concurrentes
            self._local.conn.execute('PRAGMA synchronous=NORMAL') # bon compromis perf/sécurité
        return self._local.conn

    def init_db(self):
        conn   = self._get_conn()
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS unreachable_domains (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                domain      TEXT UNIQUE NOT NULL,
                base_domain TEXT NOT NULL,
                status_code INTEGER,
                first_seen  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_check  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                log_source  TEXT,
                notified    BOOLEAN DEFAULT 0
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS check_history (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                domain           TEXT NOT NULL,
                status_code      INTEGER,
                response_time_ms INTEGER,
                check_timestamp  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(domain) REFERENCES unreachable_domains(domain)
            )
        ''')

        cursor.execute('CREATE INDEX IF NOT EXISTS idx_domain     ON unreachable_domains(domain)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_last_check ON unreachable_domains(last_check)')
        conn.commit()
        print(f"[DB] Initialisée: {self.db_path}")

    def subdomain_exists(self, domain):
        try:
            conn   = self._get_conn()
            cursor = conn.cursor()
            cursor.execute('SELECT 1 FROM unreachable_domains WHERE domain = ? LIMIT 1', (domain,))
            return cursor.fetchone() is not None
        except Exception as e:
            print(f"[DB ERROR] subdomain_exists: {e}")
            return False

    def add_subdomain_from_file(self, domain, base_domain, status_code=None):
        try:
            conn   = self._get_conn()
            cursor = conn.cursor()
            cursor.execute(
                'INSERT OR IGNORE INTO unreachable_domains (domain, base_domain, status_code, log_source) VALUES (?, ?, ?, ?)',
                (domain, base_domain, status_code, "MANUAL_LOAD")
            )
            conn.commit()
            return True
        except Exception as e:
            print(f"[DB ERROR] add_subdomain_from_file {domain}: {e}")
            return False

    def add_unreachable(self, domain, base_domain, status_code, log_source):
        try:
            conn   = self._get_conn()
            cursor = conn.cursor()
            cursor.execute('SELECT 1 FROM unreachable_domains WHERE domain = ? LIMIT 1', (domain,))
            if cursor.fetchone():
                return False  # doublon silencieux
            cursor.execute(
                'INSERT INTO unreachable_domains (domain, base_domain, status_code, log_source) VALUES (?, ?, ?, ?)',
                (domain, base_domain, status_code, log_source)
            )
            conn.commit()
            print(f"[DB] ✅ Ajouté: {domain}")
            return True
        except Exception as e:
            print(f"[DB ERROR] add_unreachable {domain}: {e}")
            return False

    def get_unreachable(self, limit=100):
        try:
            conn   = self._get_conn()
            cursor = conn.cursor()
            cursor.execute('''
                SELECT domain, base_domain, last_check
                FROM unreachable_domains
                ORDER BY last_check ASC NULLS FIRST
                LIMIT ?
            ''', (limit,))
            return cursor.fetchall()
        except Exception as e:
            print(f"[DB ERROR] get_unreachable: {e}")
            return []

    def update_check(self, domain, status_code, response_time_ms):
        try:
            conn   = self._get_conn()
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE unreachable_domains SET status_code = ?, last_check = CURRENT_TIMESTAMP WHERE domain = ?',
                (status_code, domain)
            )
            cursor.execute(
                'INSERT INTO check_history (domain, status_code, response_time_ms) VALUES (?, ?, ?)',
                (domain, status_code, response_time_ms)
            )
            conn.commit()
            return True
        except Exception as e:
            print(f"[DB ERROR] update_check {domain}: {e}")
            return False

    def mark_notified(self, domain):
        try:
            conn   = self._get_conn()
            cursor = conn.cursor()
            cursor.execute('UPDATE unreachable_domains SET notified = 1 WHERE domain = ?', (domain,))
            conn.commit()
        except Exception as e:
            print(f"[DB ERROR] mark_notified {domain}: {e}")

db = CertificateDatabase(DATABASE_FILE)

# ==================== PATHS MONITOR ====================
class PathMonitor:
    """Monitore des URLs spécifiques et envoie le contenu à Discord si 200."""

    def __init__(self, paths_file):
        self.paths_file = paths_file
        self.paths      = {}
        self.load_paths()

    def load_paths(self):
        if not os.path.exists(self.paths_file):
            print(f"[PATHS] {self.paths_file} n'existe pas (optionnel)")
            return
        try:
            with open(self.paths_file, 'r') as f:
                lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]
            for line in lines:
                if line.startswith('http'):
                    self.paths[line] = line
                    print(f"[PATHS] ✅ Chargé: {line}")
            print(f"[PATHS] Total: {len(self.paths)} paths\n")
        except Exception as e:
            print(f"[PATHS ERROR] {e}")

    def check_path(self, url):
        """Retourne (status_code, content, response_time_ms, error)."""
        try:
            response      = requests.get(url, timeout=HTTP_CHECK_TIMEOUT, verify=False, allow_redirects=True)
            response_time = int(response.elapsed.total_seconds() * 1000)
            if response.status_code == 200:
                content = response.text
                if content:
                    return (200, content, response_time, None)
                return (200, None, response_time, "Content is empty")
            return (response.status_code, None, response_time, None)
        except requests.exceptions.Timeout:
            return (None, None, HTTP_CHECK_TIMEOUT * 1000, "Timeout")
        except Exception as e:
            print(f"[PATHS CHECK ERROR] {url}: {e}")
            return (None, None, None, str(e))

    def _send_embed(self, embed):
        if DISCORD_WEBHOOK:
            try:
                requests.post(DISCORD_WEBHOOK, json={"embeds": [embed]}, timeout=10)
            except Exception as e:
                print(f"[PATHS DISCORD ERROR] {e}")

    def send_content_alert(self, url, content):
        preview = content[:1900]
        if len(content) > 1900:
            preview += f"\n... (tronqué, taille totale: {len(content)} chars)"
        embed = {
            "title":       "✅ Path Accessible - Contenu récupéré",
            "description": f"**URL:** `{url}`\n\n**Contenu:**\n```\n{preview}\n```",
            "color":       0x00ff00,
            "fields": [
                {"name": "Taille",  "value": f"{len(content)} bytes", "inline": True},
                {"name": "Status",  "value": "200 OK",                "inline": True},
            ],
            "footer":    {"text": "CT Monitor - Path Content"},
            "timestamp": datetime.utcnow().isoformat()
        }
        self._send_embed(embed)
        print(f"[PATHS ALERT] Contenu envoyé: {url}")

    def send_retrieve_failed_alert(self, url, error_msg):
        embed = {
            "title":       "⚠️ Retrieve Failed",
            "description": f"**URL:** `{url}`\n\n**Erreur:** {error_msg}",
            "color":       0xffaa00,
            "fields": [
                {"name": "Status", "value": "200 OK",                   "inline": True},
                {"name": "Issue",  "value": "Récupération du contenu échouée", "inline": True},
            ],
            "footer":    {"text": "CT Monitor - Retrieve Failed"},
            "timestamp": datetime.utcnow().isoformat()
        }
        self._send_embed(embed)
        print(f"[PATHS ALERT] ⚠️ Retrieve failed: {url} — {error_msg}")

    def send_check_failed_alert(self, url, status_code, response_time):
        status_str = str(status_code) if status_code else "timeout"
        embed = {
            "title":       "⚠️ Path Check Failed",
            "description": f"**URL:** `{url}`\n\n**Status:** {status_str}",
            "color":       0xffaa00,
            "fields": [
                {"name": "Status Code",    "value": status_str,                                  "inline": True},
                {"name": "Response Time",  "value": f"{response_time}ms" if response_time else "N/A", "inline": True},
            ],
            "footer":    {"text": "CT Monitor - Path Check Failed"},
            "timestamp": datetime.utcnow().isoformat()
        }
        self._send_embed(embed)
        print(f"[PATHS ALERT] ⚠️ Check failed: {url} [{status_str}]")

    def check_all(self):
        if not self.paths:
            return
        print(f"[PATHS CRON] Vérification de {len(self.paths)} paths...")
        for url in self.paths:
            status_code, content, response_time, error = self.check_path(url)
            if status_code == 200:
                if content:
                    self.send_content_alert(url, content)
                else:
                    self.send_retrieve_failed_alert(url, error or "Unknown error")
            else:
                self.send_check_failed_alert(url, status_code, response_time)

path_monitor = PathMonitor(PATHS_FILE)

# ==================== CHARGEMENT DOMAINES CIBLES ====================
try:
    with open(DOMAINS_FILE, 'r') as f:
        targets = {line.strip().lower() for line in f if line.strip() and not line.startswith('#')}
    print(f"[OK] {len(targets)} domaines chargés")
except Exception as e:
    print(f"[ERREUR] Chargement domaines: {e}")
    targets = set()

if not targets:
    print("[ERREUR] Aucun domaine à surveiller — arrêt.")
    exit(1)

# ==================== CHARGEMENT SUBDOMAINS MANUELS ====================
def load_subdomains_from_file():
    """
    Charge subdomains.txt au démarrage.
    Pour chaque nouveau sous-domaine :
      - Fait un HTTP check immédiat pour connaitre son état réel
      - Stocke en DB avec le status_code initial
      - Le cron job prendra ensuite le relais toutes les 5 minutes
    """
    loaded = duplicates = skipped = 0
    if not os.path.exists(SUBDOMAINS_FILE):
        print(f"[INFO] {SUBDOMAINS_FILE} n'existe pas (optionnel)")
        return loaded, duplicates
    try:
        with open(SUBDOMAINS_FILE, 'r') as f:
            subdomains = [l.strip().lower() for l in f if l.strip() and not l.startswith('#')]

        print(f"[LOAD] {len(subdomains)} sous-domaines dans {SUBDOMAINS_FILE}")

        for subdomain in subdomains:
            base_domain = next((t for t in targets if subdomain == t or subdomain.endswith('.' + t)), None)

            if not base_domain:
                print(f"[LOAD] ❌ Domaine cible introuvable pour: {subdomain}")
                skipped += 1
                continue

            if db.subdomain_exists(subdomain):
                duplicates += 1
                print(f"[LOAD] ⏭️  Déjà en DB: {subdomain}")
                continue

            # Check HTTP immédiat pour connaitre l'état réel dès le départ
            print(f"[LOAD] 🔍 Check initial: {subdomain} ...")
            status_code, response_time = check_domain(subdomain)

            db.add_subdomain_from_file(subdomain, base_domain, status_code)
            loaded += 1

            status_str = str(status_code) if status_code else "timeout"
            if status_code and 200 <= status_code < 400:
                print(f"[LOAD] ✅ {subdomain} [{status_str}] — en ligne, surveillé")
            else:
                print(f"[LOAD] 🔴 {subdomain} [{status_str}] — hors ligne, ajouté au monitoring")

        print(f"\n[LOAD] Résumé: {loaded} ajoutés | {duplicates} déjà en DB | {skipped} ignorés\n")
        return loaded, duplicates

    except Exception as e:
        print(f"[ERROR] Chargement subdomains: {e}")
        return 0, 0

# ==================== PERSISTANCE POSITIONS ====================
def load_positions():
    try:
        if os.path.exists(POSITIONS_FILE):
            with open(POSITIONS_FILE, 'r') as f:
                return json.load(f)
    except Exception:
        pass
    return {}

def save_positions():
    try:
        with open(POSITIONS_FILE, 'w') as f:
            json.dump(stats['positions'], f, indent=2)
    except Exception as e:
        print(f"[WARN] Sauvegarde positions: {e}")

stats['positions'] = load_positions()

# ==================== HTTP CHECKER ====================
def check_domain(domain):
    """
    Vérifie HTTP/HTTPS avec suivi des redirections.
    Retourne (status_code_final, response_time_ms).
    Un 301/302 n'est plus traité comme inaccessible.
    """
    for protocol in ['https', 'http']:
        try:
            start    = time.time()
            response = requests.head(
                f"{protocol}://{domain}",
                timeout=HTTP_CHECK_TIMEOUT,
                allow_redirects=True,   # ← CORRIGÉ: suit les redirections
                verify=False
            )
            elapsed = int((time.time() - start) * 1000)
            return (response.status_code, elapsed)
        except Exception:
            continue
    return (None, None)

# ==================== DISCORD ALERTS ====================
def send_discovery_alert(matched_domains_with_status, log_name):
    """Envoie un embed Discord groupé par domaine de base."""
    try:
        if not matched_domains_with_status:
            return

        by_base = {}
        for domain, status_code in matched_domains_with_status:
            base = next((t for t in targets if domain == t or domain.endswith('.' + t)), None)
            if base:
                by_base.setdefault(base, {'accessible': [], 'unreachable': []})
                # Accessible = 200 ou redirection 3xx
                # Inaccessible = 4xx, 5xx, timeout (None)
                if status_code and 200 <= status_code < 400:
                    by_base[base]['accessible'].append((domain, status_code))
                else:
                    by_base[base]['unreachable'].append((domain, status_code))

        description      = ""
        total_accessible = total_unreachable = 0

        for base, data in sorted(by_base.items()):
            description += f"\n**{base}**\n"
            if data['accessible']:
                total_accessible += len(data['accessible'])
                description += "  🟢 En ligne (2xx/3xx):\n"
                for domain, status in data['accessible']:
                    description += f"    `{domain}` [{status}]\n"
            if data['unreachable']:
                total_unreachable += len(data['unreachable'])
                description += "  🔴 Hors ligne (4xx/5xx/timeout):\n"
                for domain, status in data['unreachable']:
                    description += f"    `{domain}` [{status if status else 'timeout'}]\n"

        embed = {
            "title":       f"🚨 {len(matched_domains_with_status)} certificats découverts",
            "description": description,
            "color":       0xff8800,
            "fields": [
                {"name": "🟢 En ligne",          "value": str(total_accessible),  "inline": True},
                {"name": "🔴 Hors ligne",         "value": str(total_unreachable), "inline": True},
                {"name": "Source",                "value": log_name,               "inline": True},
            ],
            "footer":    {"text": "CT Monitor - Status Check Results"},
            "timestamp": datetime.utcnow().isoformat()
        }

        if DISCORD_WEBHOOK:
            requests.post(DISCORD_WEBHOOK, json={"embeds": [embed]}, timeout=10)

        with stats_lock:
            stats['alertes_envoyées'] += 1
            stats['dernière_alerte']   = datetime.utcnow()

        print(f"[DISCORD] {len(matched_domains_with_status)} découverts (✅{total_accessible} ❌{total_unreachable})")

    except Exception as e:
        print(f"[DISCORD ERROR] send_discovery_alert: {e}")

def send_now_accessible_alert(domain):
    """Alerte quand un domaine précédemment inaccessible répond 200."""
    try:
        embed = {
            "title":       "🟢 Domaine maintenant accessible!",
            "description": f"`{domain}` est maintenant **online** (200 OK)",
            "color":       0x00ff00,
            "footer":      {"text": "CT Monitor - Status Change"},
            "timestamp":   datetime.utcnow().isoformat()
        }
        if DISCORD_WEBHOOK:
            requests.post(DISCORD_WEBHOOK, json={"embeds": [embed]}, timeout=10)
        print(f"[ALERT] {domain} est maintenant accessible!")
    except Exception as e:
        print(f"[DISCORD ERROR] send_now_accessible_alert: {e}")

# ==================== PARSING CERTIFICATS ====================
def parse_certificate(entry):
    """
    Parse un entry CT (x509 ou pre-certificate).
    Utilise hashlib.md5 pour le hash (stable entre redémarrages, contrairement à hash()).
    Retourne la liste des domaines qui matchent les cibles.
    """
    try:
        leaf_input = entry.get('leaf_input', '')
        leaf_bytes = base64.b64decode(leaf_input)

        if len(leaf_bytes) < 12:
            return []

        log_entry_type = int.from_bytes(leaf_bytes[10:12], 'big')
        cert_der       = None

        if log_entry_type == 0:  # X509Entry
            with stats_lock:
                stats['x509_count'] += 1
            if len(leaf_bytes) < 15:
                return []
            cert_length = int.from_bytes(leaf_bytes[12:15], 'big')
            cert_end    = 15 + cert_length
            if cert_end <= len(leaf_bytes):
                cert_der = leaf_bytes[15:cert_end]

        elif log_entry_type == 1:  # PreCertificate
            with stats_lock:
                stats['precert_count'] += 1
            try:
                extra_data  = base64.b64decode(entry.get('extra_data', ''))
                if len(extra_data) > 3:
                    cert_length = int.from_bytes(extra_data[0:3], 'big')
                    if len(extra_data) >= 3 + cert_length:
                        cert_der = extra_data[3:3 + cert_length]
            except Exception:
                pass

        if not cert_der:
            with stats_lock:
                stats['parse_errors'] += 1
            return []

        cert        = x509.load_der_x509_certificate(cert_der, default_backend())
        all_domains = set()

        try:
            cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            if cn:
                all_domains.add(cn[0].value.lower())
        except Exception:
            pass

        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for san in san_ext.value:
                # Nettoyer proprement les wildcards *.domain.com → domain.com
                raw = san.value.lower()
                clean = raw.lstrip('*').lstrip('.')
                if clean:
                    all_domains.add(clean)
        except Exception:
            pass

        matched = [
            domain for domain in all_domains
            if any(domain == t or domain.endswith('.' + t) for t in targets)
        ]
        return list(set(matched))

    except Exception:
        with stats_lock:
            stats['parse_errors'] += 1
        return []

# ==================== CRON JOB - RECHECK ====================
def cron_recheck_unreachable():
    """
    Toutes les 5 minutes :
      - Revérifie les domaines inaccessibles en DB
      - Alerte Discord si un domaine devient 200
      - Vérifie les paths spécifiques
    """
    print("[CRON] Thread recheck démarré")
    while True:
        try:
            unreachable = db.get_unreachable(limit=50)
            if unreachable:
                print(f"[CRON] Recheck de {len(unreachable)} domaines...")
                for domain, base_domain, last_check in unreachable:
                    status_code, response_time = check_domain(domain)
                    db.update_check(domain, status_code, response_time)
                    # Alerte si retour en ligne (200 ou redirection 3xx)
                    if status_code and 200 <= status_code < 400:
                        send_now_accessible_alert(domain)
                        db.mark_notified(domain)
                        print(f"[CRON] ✅ {domain} est maintenant accessible! [{status_code}]")

            path_monitor.check_all()
            time.sleep(UNREACHABLE_RECHECK_INTERVAL)

        except Exception as e:
            print(f"[CRON ERROR] {e}")
            time.sleep(60)

# ==================== CT MONITORING ====================
def monitor_log(log_config):
    """Monitore un CT log : récupère les nouvelles entrées et traite les certificats."""
    log_name = log_config['name']
    log_url  = log_config['url']
    priority = log_config.get('priority', 'MEDIUM')

    # Initialisation de la position si premier démarrage
    if log_name not in stats['positions']:
        try:
            response  = requests.get(f"{log_url}/ct/v1/get-sth", timeout=10)
            tree_size = response.json()['tree_size']
            stats['positions'][log_name] = max(0, tree_size - 1000)
            print(f"[INIT] {log_name}: position initiale {stats['positions'][log_name]:,}")
        except Exception:
            return 0

    try:
        response  = requests.get(f"{log_url}/ct/v1/get-sth", timeout=10)
        tree_size = response.json()['tree_size']
    except Exception:
        return 0

    current_pos = stats['positions'][log_name]
    if current_pos >= tree_size:
        return 0

    backlog = tree_size - current_pos
    max_batches = {'CRITICAL': MAX_BATCHES_CRITICAL, 'HIGH': MAX_BATCHES_HIGH}.get(priority, MAX_BATCHES_MEDIUM)

    print(f"[{log_name}] Backlog: {backlog:,} entrées — traitement jusqu'à {max_batches * BATCH_SIZE:,}")

    batches_done  = 0
    all_results   = []
    seen_in_cycle = set()  # déduplication domaines dans ce cycle

    while current_pos < tree_size and batches_done < max_batches:
        end_pos = min(current_pos + BATCH_SIZE, tree_size)
        try:
            response = requests.get(
                f"{log_url}/ct/v1/get-entries",
                params={"start": current_pos, "end": end_pos - 1},
                timeout=30
            )
            entries = response.json().get('entries', [])
        except Exception:
            break

        if not entries:
            break

        for entry in entries:
            with stats_lock:
                stats['certificats_analysés'] += 1

            # Hash stable avec md5 (contrairement à hash() qui change entre process)
            leaf_input = entry.get('leaf_input', '')
            cert_hash  = hashlib.md5(leaf_input.encode()).hexdigest()

            if seen_certificates.contains(cert_hash):
                with stats_lock:
                    stats['duplicates_évités'] += 1
                continue

            seen_certificates.add(cert_hash)

            matched_domains = parse_certificate(entry)
            if not matched_domains:
                continue

            with stats_lock:
                stats['matches_trouvés'] += len(matched_domains)

            for domain in matched_domains:
                if domain in seen_in_cycle:
                    continue
                seen_in_cycle.add(domain)

                status_code, response_time = check_domain(domain)
                with stats_lock:
                    stats['http_checks'] += 1

                all_results.append((domain, status_code))

                # Stocker en DB tout ce qui n'est pas 200-3xx
                # 4xx, 5xx, timeout = à monitorer jusqu'au retour en ligne
                if status_code is None or status_code >= 400:
                    base = next((t for t in targets if domain == t or domain.endswith('.' + t)), None)
                    if base:
                        db.add_unreachable(domain, base, status_code, log_name)

        current_pos                   = end_pos
        stats['positions'][log_name]  = current_pos
        batches_done                 += 1
        with stats_lock:
            stats['batches_processed'] += 1

    if all_results:
        send_discovery_alert(all_results, log_name)

    return batches_done

def monitor_all_logs():
    """Lance la surveillance de tous les logs CT en parallèle."""
    results = {}
    with ThreadPoolExecutor(max_workers=PARALLEL_LOGS) as executor:
        futures = {executor.submit(monitor_log, log): log['name'] for log in ENABLED_LOGS}
        for future in as_completed(futures):
            log_name = futures[future]
            try:
                results[log_name] = future.result(timeout=TIMEOUT_PER_LOG) or 0
            except Exception as e:
                print(f"[ERROR] {log_name}: {str(e)[:100]}")
                results[log_name] = -1
    return results

# ==================== NETTOYAGE DB ====================
def cleanup_db():
    """
    Supprime les entrées invalides en DB :
    - Wildcards (*.domain) qui auraient été insérés par une ancienne version
    - Domaines qui ne matchent plus aucune cible dans domains.txt
    """
    try:
        conn   = db._get_conn()
        cursor = conn.cursor()

        # Supprimer les wildcards
        cursor.execute("DELETE FROM unreachable_domains WHERE domain LIKE '*.%'")
        wildcards_deleted = cursor.rowcount

        # Supprimer les domaines qui ne matchent plus aucune cible
        cursor.execute("SELECT domain FROM unreachable_domains")
        all_domains = [row[0] for row in cursor.fetchall()]
        orphans = [
            d for d in all_domains
            if not any(d == t or d.endswith('.' + t) for t in targets)
        ]
        for orphan in orphans:
            cursor.execute("DELETE FROM unreachable_domains WHERE domain = ?", (orphan,))

        conn.commit()

        if wildcards_deleted > 0:
            print(f"[DB CLEANUP] {wildcards_deleted} wildcard(s) supprimé(s)")
        if orphans:
            print(f"[DB CLEANUP] {len(orphans)} domaine(s) orphelin(s) supprimé(s): {orphans}")
        if wildcards_deleted == 0 and not orphans:
            print("[DB CLEANUP] Base propre, rien à nettoyer")

    except Exception as e:
        print(f"[DB CLEANUP ERROR] {e}")

# ==================== DÉMARRAGE ====================
print(f"\n[START] {NB_LOGS_ACTIFS} logs CT actifs")
print(f"[START] {len(targets)} domaine(s) surveillés: {', '.join(sorted(targets))}")
print(f"[START] Capacité: {BATCH_SIZE * MAX_BATCHES_CRITICAL:,} certs/log/cycle (CRITICAL)")
print("=" * 80 + "\n")

cleanup_db()
loaded_count, duplicate_count = load_subdomains_from_file()
print(f"[STARTUP] Subdomains chargés: {loaded_count} (doublons ignorés: {duplicate_count})\n")

# Thread cron recheck
cron_thread = threading.Thread(target=cron_recheck_unreachable, daemon=True)
cron_thread.start()
time.sleep(1)

# ==================== BOUCLE PRINCIPALE ====================
cycle = 0
while True:
    try:
        cycle      += 1
        cycle_start = time.time()

        with stats_lock:
            stats['dernière_vérification'] = datetime.utcnow()

        print(f"\n{'='*80}")
        print(f"CYCLE #{cycle} — {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"{'='*80}")

        monitor_all_logs()
        save_positions()

        cycle_duration = int(time.time() - cycle_start)

        print(f"\n[DONE] Cycle #{cycle} terminé en {cycle_duration}s")
        print(f"[STATS] Certificats analysés : {stats['certificats_analysés']:,}")
        print(f"[STATS] Matches trouvés      : {stats['matches_trouvés']:,}")
        print(f"[STATS] Alertes envoyées      : {stats['alertes_envoyées']:,}")
        print(f"[STATS] HTTP checks           : {stats['http_checks']:,}")
        print(f"[STATS] Duplicates évités     : {stats['duplicates_évités']:,}")
        print(f"[STATS] Parse errors          : {stats['parse_errors']:,}")
        print(f"{'='*80}")

        print(f"\n[WAIT] Prochain cycle dans {CHECK_INTERVAL}s...")
        time.sleep(CHECK_INTERVAL)

    except KeyboardInterrupt:
        print("\n[STOP] Arrêt demandé")
        save_positions()
        break
    except Exception as e:
        import traceback
        print(f"\n[ERROR] {e}")
        traceback.print_exc()
        save_positions()
        time.sleep(30)

print("\n[STOP] Monitoring arrêté")
