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

# Thread-safe print — défini en premier car utilisé dès le démarrage
import threading as _threading
_print_lock = _threading.Lock()

def tprint(msg):
    with _print_lock:
        print(msg)

# Supprimer les warnings SSL (verify=False intentionnel)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

tprint("=" * 80)
tprint("CT MONITORING - VERSION AMÉLIORÉE")
tprint(f"Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
tprint("=" * 80)

# ==================== CONFIGURATION ====================
DISCORD_WEBHOOK    = os.environ.get('DISCORD_WEBHOOK', '')
DOMAINS_FILE       = '/app/domains.txt'
DATA_DIR           = '/app/data'
DATABASE_FILE      = f'{DATA_DIR}/ct_monitoring.db'
POSITIONS_FILE     = f'{DATA_DIR}/ct_positions.json'
SUBDOMAINS_FILE    = '/app/subdomains.txt'   # monté depuis le repo (comme domains.txt)
PATHS_FILE         = '/app/paths.txt'        # monté depuis le repo (comme domains.txt)

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
stats_lock  = threading.Lock()

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

# ==================== CACHE NOTIFICATIONS ====================
class NotificationCache:
    # Cache TTL pour eviter de notifier plusieurs fois le meme domaine
    # dans une courte periode. Thread-safe.
    def __init__(self, ttl_seconds=3600):
        self.cache = {}
        self.ttl   = ttl_seconds
        self.lock  = threading.Lock()

    def already_notified(self, domain):
        with self.lock:
            if domain in self.cache:
                if time.time() - self.cache[domain] < self.ttl:
                    return True
                del self.cache[domain]
            return False

    def mark(self, domain):
        with self.lock:
            self.cache[domain] = time.time()

    def clear_expired(self):
        with self.lock:
            now     = time.time()
            expired = [d for d, t in self.cache.items() if now - t >= self.ttl]
            for d in expired:
                del self.cache[d]
            return len(expired)

# TTL 6h : un domaine ne sera pas renotifie dans Discord pendant 6 heures
NOTIFICATION_TTL = 6 * 3600
notif_cache = NotificationCache(ttl_seconds=NOTIFICATION_TTL)

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

        # Table principale — tous les sous-domaines découverts
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS subdomains (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                domain      TEXT UNIQUE NOT NULL,
                base_domain TEXT NOT NULL,
                status_code INTEGER,
                is_online   BOOLEAN DEFAULT 0,
                first_seen  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_check  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                log_source  TEXT
            )
        ''')

        # Historique des checks
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS check_history (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                domain           TEXT NOT NULL,
                status_code      INTEGER,
                response_time_ms INTEGER,
                check_timestamp  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Migration: si l ancienne table existe, copier les données
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='unreachable_domains'")
        if cursor.fetchone():
            cursor.execute('''
                INSERT OR IGNORE INTO subdomains (domain, base_domain, status_code, is_online, first_seen, last_check, log_source)
                SELECT domain, base_domain, status_code, 0, first_seen, last_check, log_source
                FROM unreachable_domains
            ''')
            cursor.execute('DROP TABLE unreachable_domains')
            tprint("[DB] Migration unreachable_domains → subdomains effectuée")

        cursor.execute('CREATE INDEX IF NOT EXISTS idx_domain     ON subdomains(domain)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_last_check ON subdomains(last_check)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_is_online  ON subdomains(is_online)')
        conn.commit()
        tprint(f"[DB] Initialisée: {self.db_path}")

    def subdomain_exists(self, domain):
        try:
            conn   = self._get_conn()
            cursor = conn.cursor()
            cursor.execute('SELECT 1 FROM subdomains WHERE domain = ? LIMIT 1', (domain,))
            return cursor.fetchone() is not None
        except Exception as e:
            tprint(f"[DB ERROR] subdomain_exists: {e}")
            return False

    def add_domain(self, domain, base_domain, status_code, log_source):
        is_online = 1 if status_code == 200 else 0
        try:
            conn   = self._get_conn()
            cursor = conn.cursor()
            cursor.execute('SELECT 1 FROM subdomains WHERE domain = ? LIMIT 1', (domain,))
            if cursor.fetchone():
                cursor.execute(
                    'UPDATE subdomains SET status_code = ?, is_online = ?, last_check = CURRENT_TIMESTAMP WHERE domain = ?',
                    (status_code, is_online, domain)
                )
                conn.commit()
                return False
            cursor.execute(
                'INSERT INTO subdomains (domain, base_domain, status_code, is_online, log_source) VALUES (?, ?, ?, ?, ?)',
                (domain, base_domain, status_code, is_online, log_source)
            )
            conn.commit()
            tprint(f"[DB] Nouveau: {domain} [{status_code if status_code else 'timeout'}]")
            return True
        except Exception as e:
            tprint(f"[DB ERROR] add_domain {domain}: {e}")
            return False

    def add_subdomain_from_file(self, domain, base_domain, status_code=None):
        is_online = 1 if status_code == 200 else 0
        try:
            conn   = self._get_conn()
            cursor = conn.cursor()
            cursor.execute(
                'INSERT OR IGNORE INTO subdomains (domain, base_domain, status_code, is_online, log_source) VALUES (?, ?, ?, ?, ?)',
                (domain, base_domain, status_code, is_online, "MANUAL_LOAD")
            )
            conn.commit()
            return True
        except Exception as e:
            tprint(f"[DB ERROR] add_subdomain_from_file {domain}: {e}")
            return False

    def get_offline(self, limit=100):
        try:
            conn   = self._get_conn()
            cursor = conn.cursor()
            cursor.execute('''
                SELECT domain, base_domain, last_check
                FROM subdomains
                WHERE is_online = 0
                ORDER BY last_check ASC NULLS FIRST
                LIMIT ?
            ''', (limit,))
            return cursor.fetchall()
        except Exception as e:
            tprint(f"[DB ERROR] get_offline: {e}")
            return []

    def get_all_domains(self):
        try:
            conn   = self._get_conn()
            cursor = conn.cursor()
            cursor.execute('SELECT domain FROM subdomains ORDER BY domain')
            return [row[0] for row in cursor.fetchall()]
        except Exception as e:
            tprint(f"[DB ERROR] get_all_domains: {e}")
            return []

    def update_check(self, domain, status_code, response_time_ms):
        is_online = 1 if status_code == 200 else 0
        try:
            conn   = self._get_conn()
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE subdomains SET status_code = ?, is_online = ?, last_check = CURRENT_TIMESTAMP WHERE domain = ?',
                (status_code, is_online, domain)
            )
            cursor.execute(
                'INSERT INTO check_history (domain, status_code, response_time_ms) VALUES (?, ?, ?)',
                (domain, status_code, response_time_ms)
            )
            conn.commit()
            return True
        except Exception as e:
            tprint(f"[DB ERROR] update_check {domain}: {e}")
            return False

    def mark_online(self, domain, status_code):
        try:
            conn   = self._get_conn()
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE subdomains SET is_online = 1, status_code = ?, last_check = CURRENT_TIMESTAMP WHERE domain = ?',
                (status_code, domain)
            )
            conn.commit()
            tprint(f"[DB] {domain} marque online [{status_code}]")
        except Exception as e:
            tprint(f"[DB ERROR] mark_online {domain}: {e}")
    def count(self):
        """Retourne le nombre de domaines en monitoring."""
        try:
            conn   = self._get_conn()
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM subdomains')
            return cursor.fetchone()[0]
        except Exception as e:
            return 0

    def size_mb(self):
        """Retourne la taille de la DB en MB."""
        try:
            size = os.path.getsize(self.db_path)
            return round(size / 1024 / 1024, 2)
        except Exception:
            return 0

    def stats_summary(self):
        """Retourne un résumé: total domaines, dont combien par status."""
        try:
            conn   = self._get_conn()
            cursor = conn.cursor()
            cursor.execute('''
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN is_online = 1 THEN 1 ELSE 0 END) as online,
                    SUM(CASE WHEN is_online = 0 AND status_code IS NULL THEN 1 ELSE 0 END) as timeouts,
                    SUM(CASE WHEN status_code >= 400 AND status_code < 500 THEN 1 ELSE 0 END) as errors_4xx,
                    SUM(CASE WHEN status_code >= 500 THEN 1 ELSE 0 END) as errors_5xx
                FROM subdomains
            ''')
            row = cursor.fetchone()
            return {
                'total':    row[0],
                'online':   row[1],
                'timeout':  row[2],
                '4xx':      row[3],
                '5xx':      row[4],
            }
        except Exception:
            return {'total': 0, 'online': 0, 'timeout': 0, '4xx': 0, '5xx': 0}

db = CertificateDatabase(DATABASE_FILE)

# ==================== PATHS MONITOR ====================
class PathMonitor:
    # Paths predefinies — chargees depuis paths.txt + defaults integres
    DEFAULT_PATHS = [
        "/.env",
        "/.env.backup",
        "/.env.old",
        "/.env.prod",
        "/.env.production",
        "/.env.local",
        "/.git/config",
        "/.git/HEAD",
        "/wp-config.php",
        "/config.php",
        "/actuator/env",
        "/actuator/beans",
        "/api/v1/users",
        "/backup.sql",
        "/dump.sql",
    ]

    def __init__(self, paths_file):
        self.paths_file = paths_file
        self.paths      = list(self.DEFAULT_PATHS)
        self.load_paths()

    def load_paths(self):
        if not os.path.exists(self.paths_file):
            tprint(f"[PATHS] {self.paths_file} absent — utilisation des paths par defaut ({len(self.paths)})")
            return
        try:
            with open(self.paths_file, 'r') as f:
                custom = [l.strip() for l in f if l.strip() and not l.startswith('#')]
            # Fusionner defaults + custom sans doublons
            for p in custom:
                if p not in self.paths:
                    self.paths.append(p)
            tprint(f"[PATHS] {len(self.DEFAULT_PATHS)} paths par defaut + {len(custom)} custom = {len(self.paths)} total")
        except Exception as e:
            tprint(f"[PATHS ERROR] {e}")

    def check_path(self, url):
        try:
            response      = requests.get(url, timeout=HTTP_CHECK_TIMEOUT, verify=False, allow_redirects=True,
                                         headers={'User-Agent': 'Mozilla/5.0 (compatible; CTMonitor/1.0)'})
            response_time = int(response.elapsed.total_seconds() * 1000)
            if response.status_code == 200:
                # Vérifier si c'est un WAF block
                waf, reason = is_waf_block(response)
                if waf:
                    return (403, None, response_time, f"WAF: {reason}")
                
                content = response.text
                
                # Validation: le contenu doit avoir une taille minimale (> 200 bytes)
                # pour éviter les pages vides ou de redirection
                if content and len(content) > 200:
                    return (200, content, response_time, None)
                elif content:
                    return (403, None, response_time, "Content too small (< 200 bytes)")
                else:
                    return (403, None, response_time, "Content is empty")
            return (response.status_code, None, response_time, None)
        except requests.exceptions.Timeout:
            return (None, None, HTTP_CHECK_TIMEOUT * 1000, "Timeout")
        except Exception as e:
            return (None, None, None, str(e))

    def _send_embed(self, embed):
        if DISCORD_WEBHOOK:
            try:
                requests.post(DISCORD_WEBHOOK, json={"embeds": [embed]}, timeout=10)
            except Exception as e:
                tprint(f"[PATHS DISCORD ERROR] {e}")

    def send_content_alert(self, url, content):
        preview = content[:1900]
        if len(content) > 1900:
            preview += f"\n... (tronque, taille totale: {len(content)} chars)"
        embed = {
            "title":       "✅ Fichier sensible accessible",
            "description": f"`{url}`\n\n```\n{preview}\n```",
            "color":       0x00ff00,
            "fields": [
                {"name": "Taille",  "value": f"{len(content)} bytes", "inline": True},
                {"name": "Status",  "value": "200 OK",                "inline": True},
            ],
            "footer":    {"text": "CT Monitor"},
            "timestamp": datetime.utcnow().isoformat()
        }
        self._send_embed(embed)
        tprint(f"[PATHS ALERT] Fichier sensible: {url}")

    def check_domain(self, domain):
        host, port = parse_subdomain_entry(domain)
        found      = 0
        errors     = 0
        checked    = 0
        for path in self.paths:
            for protocol in ['https', 'http']:
                url = f"{protocol}://{host}{path}"
                status_code, content, response_time, error = self.check_path(url)
                checked += 1
                if status_code == 200 and content:
                    tprint(f"[PATHS] ✅ TROUVE: {url} [{len(content)} bytes]")
                    self.send_content_alert(url, content)
                    found += 1
                    break
                elif error:
                    errors += 1
                    break  # timeout/erreur reseau sur ce path, passe au suivant
                else:
                    break  # 4xx/5xx = path n existe pas, passe au suivant
        return found, checked, errors

    def check_all(self):
        all_domains = db.get_all_domains()
        if not all_domains:
            tprint("[PATHS CRON] Aucun domaine en DB")
            return

        total_requests = len(self.paths) * len(all_domains)
        tprint(f"[PATHS CRON] Debut scan — {len(all_domains)} domaines x {len(self.paths)} paths = {total_requests} requetes max")

        total_found  = 0
        total_checked = 0
        total_errors  = 0
        start = time.time()

        for i, domain in enumerate(all_domains, 1):
            found, checked, errors = self.check_domain(domain)
            total_found   += found
            total_checked += checked
            total_errors  += errors
            # Log de progression tous les 10 domaines
            if i % 10 == 0:
                tprint(f"[PATHS CRON] Progression: {i}/{len(all_domains)} domaines scannés...")

        elapsed = int(time.time() - start)
        tprint(f"[PATHS CRON] Scan terminé en {elapsed}s")
        tprint(f"[PATHS CRON] Requetes: {total_checked} effectuées | {total_errors} erreurs réseau")
        if total_found > 0:
            tprint(f"[PATHS CRON] {total_found} fichier(s) sensible(s) trouvé(s) !")
        else:
            tprint(f"[PATHS CRON] Aucun fichier sensible trouvé")
path_monitor = PathMonitor(PATHS_FILE)

# ==================== CHARGEMENT DOMAINES CIBLES ====================
try:
    with open(DOMAINS_FILE, 'r') as f:
        targets = {line.strip().lower() for line in f if line.strip() and not line.startswith('#')}
    tprint(f"[OK] {len(targets)} domaines chargés")
except Exception as e:
    tprint(f"[ERREUR] Chargement domaines: {e}")
    targets = set()

if not targets:
    tprint("[ERREUR] Aucun domaine à surveiller — arrêt.")
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
        tprint(f"[INFO] {SUBDOMAINS_FILE} n'existe pas (optionnel)")
        return loaded, duplicates
    try:
        with open(SUBDOMAINS_FILE, 'r') as f:
            subdomains = [l.strip().lower() for l in f if l.strip() and not l.startswith('#')]

        tprint(f"[LOAD] {len(subdomains)} sous-domaines dans {SUBDOMAINS_FILE}")

        for entry in subdomains:
            subdomain, port = parse_subdomain_entry(entry)
            db_key = entry  # clé en DB = entrée brute (ex: sub.domain.com:8443)

            base_domain = next((t for t in targets if subdomain == t or subdomain.endswith('.' + t)), subdomain)

            if db.subdomain_exists(db_key):
                duplicates += 1
                tprint(f"[LOAD] ⏭️  Déjà en DB: {db_key}")
                continue

            # Check HTTP standard
            tprint(f"[LOAD] 🔍 Check initial: {subdomain} ...")
            status_code, response_time = check_domain(subdomain)

            # Check port supplémentaire si spécifié
            if port:
                port_open, port_time = check_port(subdomain, port)
                port_str = f"port {port}: {'ouvert' if port_open else 'fermé'}"
                tprint(f"[LOAD] 🔌 {subdomain}:{port} — {port_str}")

            db.add_subdomain_from_file(db_key, base_domain, status_code)
            loaded += 1

            status_str = str(status_code) if status_code else "timeout"
            if status_code == 200:
                tprint(f"[LOAD] ✅ {db_key} [{status_str}] — en ligne, surveillé")
            else:
                tprint(f"[LOAD] 🔴 {db_key} [{status_str}] — hors ligne, ajouté au monitoring")

        tprint(f"[LOAD] Résumé: {loaded} ajoutés | {duplicates} déjà en DB | {skipped} ignorés")
        return loaded, duplicates

    except Exception as e:
        tprint(f"[ERROR] Chargement subdomains: {e}")
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
        tprint(f"[WARN] Sauvegarde positions: {e}")

stats['positions'] = load_positions()

# ==================== HTTP CHECKER ====================
# Signatures WAF détectées dans les headers de réponse
# Signatures de BLOCAGE WAF dans le body
# On detecte uniquement les pages d erreur/blocage, pas la simple presence d un WAF
WAF_BLOCK_BODY_SIGNATURES = [
    'you have been blocked',
    'this request has been blocked',
    'access denied',
    'your access to this site has been limited',
    'sorry, you have been blocked',
    '__cf_chl_opt',
    'cf-please-wait',
    'checking your browser before accessing',
    'sucuri website firewall - access denied',
    'incapsula incident id',
    '_incapsula_resource',
    'incapsula_error',
    'mod_security',
    'request rejected',
    'forbidden by policy',
    'security policy violation',
    'robots" content="noindex',
    # Pages d'erreur personnalisées
    'pagina de eroare',  # Erreur en roumain
    'página de error',   # Erreur en espagnol
    'page d\'erreur',    # Erreur en français
    'error page',        # Erreur en anglais
    'eroare',            # Erreur en roumain
    'NotFoundException',
    'not found',
    'endpoint not found',
    'resource not found',
]

def is_waf_block(response):
    # Detecte uniquement les pages de BLOCAGE WAF et erreurs
    # Un site servi par Cloudflare avec vrai contenu → False
    # Une page de blocage Cloudflare/Incapsula → True
    # Une page d'erreur 404 déguisée en 200 → True
    headers      = {k.lower(): v.lower() for k, v in response.headers.items()}
    content_type = headers.get('content-type', '')

    if 'text/html' not in content_type:
        return (False, None)

    try:
        body     = response.text[:8000].lower()
        is_short = len(body) < 2000

        for sig in WAF_BLOCK_BODY_SIGNATURES:
            if sig in body:
                return (True, f"WAF/Error: '{sig}'")

        # Cloudflare JS challenge : page courte avec challenge/captcha
        if is_short and 'cloudflare' in body and ('challenge' in body or 'captcha' in body):
            return (True, "WAF block: cloudflare challenge")
        
        # Incapsula: page très courte avec Incapsula resource + robots noindex
        if is_short and '_incapsula_resource' in body and 'noindex' in body:
            return (True, "WAF block: incapsula")

    except Exception:
        pass

    return (False, None)


def check_domain(domain):
    """
    Vérifie HTTP/HTTPS avec suivi des redirections.
    Fait un GET (pas HEAD) pour pouvoir analyser le body et détecter les WAF.
    Retourne (status_code_effectif, response_time_ms).
    Si 200 mais WAF détecté → retourne (403, elapsed) pour signaler l'inaccessibilité réelle.
    """
    # Multiple User-Agents pour éviter les blocages
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    ]
    
    for protocol in ['https', 'http']:
        try:
            start    = time.time()
            response = requests.get(
                f"{protocol}://{domain}",
                timeout=HTTP_CHECK_TIMEOUT,
                allow_redirects=True,
                verify=False,
                headers={'User-Agent': user_agents[hash(domain) % len(user_agents)]},
                stream=True  # ne télécharge pas tout le body immédiatement
            )
            elapsed = int((time.time() - start) * 1000)

            # Vérifier si une redirection s'est produite
            requested_url = f"{protocol}://{domain}"
            if response.url != requested_url and response.url.lower() != f"{protocol}://{domain.lower()}/":
                tprint(f"[REDIRECT] {domain} → {response.url}")

            # Si 200 : vérifier si c'est un vrai 200 ou un WAF
            if response.status_code == 200:
                waf, reason = is_waf_block(response)
                if waf:
                    tprint(f"[WAF] {domain} → 200 bloqué par WAF ({reason})")
                    return (403, elapsed)  # traité comme inaccessible
                return (200, elapsed)

            return (response.status_code, elapsed)

        except Exception:
            continue
    return (None, None)

def check_port(host, port, timeout=10):
    """Vérifie si un port TCP est ouvert. Retourne (open, response_time_ms)."""
    import socket
    try:
        start  = time.time()
        sock   = socket.create_connection((host, port), timeout=timeout)
        elapsed = int((time.time() - start) * 1000)
        sock.close()
        return (True, elapsed)
    except Exception:
        return (False, None)

def parse_subdomain_entry(entry):
    """
    Parse une entrée de subdomains.txt.
    Formats acceptés:
      - sous.domain.com          → domain=sous.domain.com, port=None
      - sous.domain.com:8443     → domain=sous.domain.com, port=8443
    Retourne (domain, port_or_None).
    """
    entry = entry.strip().lower()
    if ':' in entry:
        parts = entry.rsplit(':', 1)
        try:
            port = int(parts[1])
            return (parts[0], port)
        except ValueError:
            return (entry, None)
    return (entry, None)

# ==================== DISCORD ALERTS ====================
def send_discovery_alert(matched_domains_with_status, log_name):
    """Envoie un embed Discord groupe par domaine de base."""
    try:
        if not matched_domains_with_status:
            return

        # Filtrer les domaines deja notifies recemment (cache TTL 6h)
        filtered = []
        skipped  = 0
        for domain, status_code in matched_domains_with_status:
            if notif_cache.already_notified(domain):
                skipped += 1
            else:
                filtered.append((domain, status_code))
                notif_cache.mark(domain)

        if skipped > 0:
            tprint(f"[DISCORD] {skipped} domaine(s) ignores - deja notifies recemment")

        if not filtered:
            return

        by_base = {}
        for domain, status_code in filtered:
            base = next((t for t in targets if domain == t or domain.endswith('.' + t)), None)
            if base:
                by_base.setdefault(base, {'accessible': [], 'unreachable': []})
                # FIX: Accessible = SEULEMENT 200 OK
                # Inaccessible = tout le reste (4xx, 5xx, timeout, 3xx, etc)
                if status_code == 200:
                    by_base[base]['accessible'].append((domain, status_code))
                else:
                    by_base[base]['unreachable'].append((domain, status_code))

        description      = ""
        total_accessible = total_unreachable = 0

        for base, data in sorted(by_base.items()):
            description += f"\n**{base}**\n"
            if data['accessible']:
                total_accessible += len(data['accessible'])
                description += "  En ligne:\n"
                for domain, status in data['accessible']:
                    description += f"    `{domain}` [{status}]\n"
            if data['unreachable']:
                total_unreachable += len(data['unreachable'])
                description += "  Hors ligne:\n"
                for domain, status in data['unreachable']:
                    description += f"    `{domain}` [{status if status else 'timeout'}]\n"

        embed = {
            "title":       f"Nouveaux certificats — {len(filtered)} domaine(s)",
            "description": description,
            "color":       0x5865f2,
            "fields": [
                {"name": "En ligne",   "value": str(total_accessible),  "inline": True},
                {"name": "Hors ligne", "value": str(total_unreachable), "inline": True},
                {"name": "Source",     "value": log_name,               "inline": True},
            ],
            "footer":    {"text": "CT Monitor"},
            "timestamp": datetime.utcnow().isoformat()
        }

        if DISCORD_WEBHOOK:
            requests.post(DISCORD_WEBHOOK, json={"embeds": [embed]}, timeout=10)

        with stats_lock:
            stats['alertes_envoyées'] += 1
            stats['dernière_alerte']   = datetime.utcnow()

        tprint(f"[DISCORD] {len(matched_domains_with_status)} découverts (✅{total_accessible} ❌{total_unreachable})")

    except Exception as e:
        tprint(f"[DISCORD ERROR] send_discovery_alert: {e}")

def send_now_accessible_alert(domain):
    """Alerte quand un domaine précédemment inaccessible répond 200."""
    try:
        embed = {
            "title":       f"🟢 {domain}",
            "description": "Ce domaine est maintenant accessible (200 OK)",
            "color":       0x00ff00,
            "footer":      {"text": "CT Monitor"},
            "timestamp":   datetime.utcnow().isoformat()
        }
        if DISCORD_WEBHOOK:
            requests.post(DISCORD_WEBHOOK, json={"embeds": [embed]}, timeout=10)
        tprint(f"[ALERT] {domain} est maintenant accessible!")
    except Exception as e:
        tprint(f"[DISCORD ERROR] send_now_accessible_alert: {e}")

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
                raw = san.value.lower()
                # Supprimer le préfixe wildcard *. si présent (ex: *.domain.com → domain.com)
                if raw.startswith('*.'):
                    raw = raw[2:]
                if raw and '.' in raw:
                    all_domains.add(raw)
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
      - Revérifie tous les domaines en DB
      - Si redevenu accessible : alerte Discord + suppression de la DB
      - Si toujours inaccessible : update last_check et log
      - Vérifie les paths spécifiques
    """
    tprint("[CRON] Thread recheck démarré")
    while True:
        try:
            domains = db.get_offline(limit=100)
            total   = db.count()

            tprint(f"[CRON] ---- Recheck démarré — {total} domaine(s) en monitoring ----")

            if not domains:
                tprint("[CRON] Aucun domaine à recheck")
            else:
                back_online = 0
                still_down  = 0

                for domain, base_domain, last_check in domains:
                    # Extraire host et port si format host:port
                    host, port = parse_subdomain_entry(domain)

                    # Check HTTP standard sur le host
                    status_code, response_time = check_domain(host)

                    # Check port additionnel si spécifié
                    port_status = ""
                    if port:
                        port_open, port_time = check_port(host, port)
                        port_status = f" | port {port}: {'ouvert' if port_open else 'fermé'}"
                        if port_open and (not status_code or status_code >= 400):
                            # Port ouvert mais HTTP pas ok → considérer accessible
                            status_code = 200
                            tprint(f"[CRON] 🔌 {domain} — port {port} ouvert")

                    status_str = str(status_code) if status_code else "timeout"

                    if status_code == 200:
                        tprint(f"[CRON] ✅ {domain} [{status_str}]{port_status} — redevenu accessible!")
                        send_now_accessible_alert(domain)
                        db.mark_online(domain, status_code)
                        back_online += 1
                    else:
                        db.update_check(domain, status_code, response_time)
                        tprint(f"[CRON] 🔴 {domain} [{status_str}]{port_status} — toujours hors ligne")
                        still_down += 1

                tprint(f"[CRON] Résumé: {back_online} redevenu(s) en ligne | {still_down} toujours hors ligne")

            path_monitor.check_all()
            tprint(f"[CRON] Prochain recheck dans {UNREACHABLE_RECHECK_INTERVAL}s")
            time.sleep(UNREACHABLE_RECHECK_INTERVAL)

        except Exception as e:
            tprint(f"[CRON ERROR] {e}")
            import traceback
            traceback.print_exc()
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
            tprint(f"[INIT] {log_name}: position initiale {stats['positions'][log_name]:,}")
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

    tprint(f"[{log_name}] Backlog: {backlog:,} entrées — traitement jusqu'à {max_batches * BATCH_SIZE:,}")

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

                # Stocker TOUS les domaines en DB (200 ou pas)
                base = next((t for t in targets if domain == t or domain.endswith('.' + t)), None)
                if base:
                    db.add_domain(domain, base, status_code, log_name)

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
                tprint(f"[ERROR] {log_name}: {str(e)[:100]}")
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
        cursor.execute("DELETE FROM subdomains WHERE domain LIKE '*.%'")
        wildcards_deleted = cursor.rowcount

        # Supprimer les domaines qui ne matchent plus aucune cible
        cursor.execute("SELECT domain FROM subdomains")
        all_domains = [row[0] for row in cursor.fetchall()]
        orphans = [
            d for d in all_domains
            if not any(d == t or d.endswith('.' + t) for t in targets)
        ]
        for orphan in orphans:
            cursor.execute("DELETE FROM subdomains WHERE domain = ?", (orphan,))

        conn.commit()

        if wildcards_deleted > 0:
            tprint(f"[DB CLEANUP] {wildcards_deleted} wildcard(s) supprimé(s)")
        if orphans:
            tprint(f"[DB CLEANUP] {len(orphans)} domaine(s) orphelin(s) supprimé(s): {orphans}")
        if wildcards_deleted == 0 and not orphans:
            tprint("[DB CLEANUP] Base propre, rien à nettoyer")

    except Exception as e:
        tprint(f"[DB CLEANUP ERROR] {e}")

# ==================== DUMP DB (variable DUMP_DB=1) ====================
def dump_db():
    tprint("[DUMP] Envoi du contenu de la DB sur Discord...")
    try:
        conn   = db._get_conn()
        cursor = conn.cursor()
        summary = db.stats_summary()

        # Message d'en-tête
        header_embed = {
            "title": "Base de données — Dump complet",
            "description": (
                f"**Total:** {summary['total']} domaine(s) en monitoring\n"
                f"**Taille:** {db.size_mb()} MB\n"
                f"**Timeout:** {summary['timeout']} | **4xx:** {summary['4xx']} | **5xx:** {summary['5xx']}"
            ),
            "color": 0x5865f2,
            "footer": {"text": "CT Monitor — DUMP_DB"},
            "timestamp": datetime.utcnow().isoformat()
        }
        requests.post(DISCORD_WEBHOOK, json={"embeds": [header_embed]}, timeout=10)

        # Envoyer les domaines par groupes de 20 (limite Discord)
        cursor.execute('''
            SELECT domain, status_code, log_source, last_check
            FROM subdomains
            ORDER BY last_check DESC
        ''')
        rows = cursor.fetchall()

        chunk_size = 20
        for i in range(0, len(rows), chunk_size):
            chunk = rows[i:i+chunk_size]
            lines = []
            for domain, status, source, last_check in chunk:
                status_str = str(status) if status else "timeout"
                last_check_str = last_check[:16] if last_check else "jamais"
                lines.append(f"`{domain}` [{status_str}] — {last_check_str}")

            embed = {
                "title": f"Domaines {i+1}–{i+len(chunk)} / {len(rows)}",
                "description": "\n".join(lines),
                "color": 0x2f3136,
                "footer": {"text": "CT Monitor — DUMP_DB"},
            }
            requests.post(DISCORD_WEBHOOK, json={"embeds": [embed]}, timeout=10)
            time.sleep(0.5)  # eviter rate limit Discord

        # Message de fin
        end_embed = {
            "title": "Dump terminé",
            "description": "Retire `DUMP_DB=1` dans Railway pour relancer le monitoring.",
            "color": 0x00ff00,
            "footer": {"text": "CT Monitor — DUMP_DB"},
        }
        requests.post(DISCORD_WEBHOOK, json={"embeds": [end_embed]}, timeout=10)
        tprint(f"[DUMP] {len(rows)} domaine(s) envoyés sur Discord")

    except Exception as e:
        tprint(f"[DUMP ERROR] {e}")
        if DISCORD_WEBHOOK:
            requests.post(DISCORD_WEBHOOK, json={"embeds": [{
                "title": "Dump erreur",
                "description": str(e),
                "color": 0xff0000
            }]}, timeout=10)

# Si DUMP_DB=1 → envoyer la DB sur Discord et quitter
if os.environ.get('DUMP_DB', '0') == '1':
    tprint("[DUMP] Mode DUMP_DB activé — envoi sur Discord...")
    dump_db()
    tprint("[DUMP] Terminé — arrêt du container")
    exit(0)

# ==================== DÉMARRAGE ====================
tprint("[START] ================================================")
tprint(f"[START] CT Monitor démarré")
tprint(f"[START] {NB_LOGS_ACTIFS} logs CT actifs")
tprint(f"[START] {len(targets)} domaine(s) surveillés: {', '.join(sorted(targets))}")
tprint(f"[START] Capacité max: {BATCH_SIZE * MAX_BATCHES_CRITICAL:,} certs/log/cycle (CRITICAL)")
tprint("[START] ================================================")

# Nettoyage DB au démarrage (wildcards, orphelins)
tprint("[STARTUP] Etape 1/3 — Nettoyage base de données...")
cleanup_db()
_db_stats = db.stats_summary()
tprint(f"[STARTUP] DB: {_db_stats['total']} domaines | online={_db_stats['online']} | offline={_db_stats['total']-_db_stats['online']} | {db.size_mb()} MB")
tprint(f"[STARTUP] DB detail: {_db_stats['timeout']} timeout | {_db_stats['4xx']} 4xx | {_db_stats['5xx']} 5xx")

# Chargement subdomains manuels
tprint(f"[STARTUP] Etape 2/3 — Chargement {SUBDOMAINS_FILE}...")
if not os.path.exists(SUBDOMAINS_FILE):
    tprint(f"[STARTUP] {SUBDOMAINS_FILE} absent — aucun sous-domaine manuel à charger")
else:
    loaded_count, duplicate_count = load_subdomains_from_file()
    tprint(f"[STARTUP] Subdomains: {loaded_count} nouveau(x) ajouté(s), {duplicate_count} déjà en DB")
    _db_stats = db.stats_summary()
    tprint(f"[STARTUP] DB après chargement: {_db_stats['total']} domaine(s) en monitoring | {db.size_mb()} MB")

# Démarrage thread cron
tprint("[STARTUP] Etape 3/3 — Démarrage thread cron recheck...")
cron_thread = threading.Thread(target=cron_recheck_unreachable, daemon=True)
cron_thread.start()
time.sleep(1)
tprint("[STARTUP] Thread cron démarré — recheck toutes les 5 minutes")
tprint("[STARTUP] ================================================")
tprint("[STARTUP] Démarrage boucle principale CT monitoring...")
tprint("[STARTUP] ================================================")

# ==================== BOUCLE PRINCIPALE ====================
cycle = 0
while True:
    try:
        cycle      += 1
        cycle_start = time.time()

        with stats_lock:
            stats['dernière_vérification'] = datetime.utcnow()

        tprint(f"[CYCLE #{cycle}] ---- {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} ----")

        monitor_all_logs()
        save_positions()

        cycle_duration = int(time.time() - cycle_start)

        _db_stats = db.stats_summary()
        tprint(f"[CYCLE #{cycle}] Terminé en {cycle_duration}s")
        tprint(f"[CYCLE #{cycle}] Certificats analysés : {stats['certificats_analysés']:,}")
        tprint(f"[CYCLE #{cycle}] Matches trouvés      : {stats['matches_trouvés']:,}")
        tprint(f"[CYCLE #{cycle}] HTTP checks          : {stats['http_checks']:,}")
        tprint(f"[CYCLE #{cycle}] Alertes envoyées     : {stats['alertes_envoyées']:,}")
        tprint(f"[CYCLE #{cycle}] Duplicates évités    : {stats['duplicates_évités']:,}")
        tprint(f"[CYCLE #{cycle}] DB monitoring        : {_db_stats['total']} domaine(s) | {db.size_mb()} MB")
        tprint(f"[CYCLE #{cycle}] DB detail            : {_db_stats['timeout']} timeout | {_db_stats['4xx']} 4xx | {_db_stats['5xx']} 5xx")
        tprint(f"[CYCLE #{cycle}] Prochain cycle dans {CHECK_INTERVAL}s...")
        time.sleep(CHECK_INTERVAL)

    except KeyboardInterrupt:
        tprint("[STOP] Arrêt demandé")
        save_positions()
        break
    except Exception as e:
        import traceback
        tprint(f"[ERROR] {e}")
        traceback.print_exc()
        save_positions()
        time.sleep(30)

tprint("[STOP] Monitoring arrêté")
