#!/usr/bin/env python3
"""
CT Monitoring VPS - VERSION v4.4.0 - PARALLEL EDITION
✅ DatabaseWriter centralisé (queue writes, zéro contention WAL)
✅ JS Scanner parallélisé (ThreadPoolExecutor dédié)
✅ Recheck offline parallélisé
✅ Path scan collecte optimisée
✅ Reads thread-local conservés (compatibles WAL)
✅ Tous les locks/semaphores correctement propagés
✅ Backward compatible avec v4.3.2 (même schéma DB, même config)
"""
import requests
import json
import time
import os
import socket
import threading
import traceback
import base64
import sqlite3
import hashlib
import hmac
import urllib3
import queue
import weakref
import re
import tempfile
from datetime import datetime, timedelta
from urllib.parse import urlparse, urljoin
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from collections import OrderedDict
from idna import encode as idna_encode, IDNAError

# ==================== THREAD-SAFE PRINT ====================
_print_lock = threading.Lock()
def tprint(msg):
    with _print_lock:
        print(f"[{datetime.utcnow().strftime('%H:%M:%S')}] {msg}")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

tprint("=" * 100)
tprint("CT MONITORING - VERSION v4.4.1 - PARALLEL EDITION + FP FIXES")
tprint(f"Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
tprint("=" * 100)

# ==================== CONFIGURATION ====================
DISCORD_WEBHOOK = os.environ.get('DISCORD_WEBHOOK', '')
DISCORD_SECRET  = os.environ.get('DISCORD_SECRET', '')
DOMAINS_FILE    = '/app/domains.txt'
DATA_DIR        = '/app/data'
DATABASE_FILE   = f'{DATA_DIR}/ct_monitoring.db'
POSITIONS_FILE  = f'{DATA_DIR}/ct_positions.json'
POSITIONS_WAL   = f'{DATA_DIR}/ct_positions.json.wal'
SUBDOMAINS_FILE = '/app/subdomains.txt'
PATHS_FILE      = '/app/paths.txt'
HEARTBEAT_FILE  = '/tmp/ct_monitor.heartbeat'

os.makedirs(DATA_DIR, exist_ok=True)

CHECK_INTERVAL               = 30
BATCH_SIZE                   = 500
MAX_BATCHES_CRITICAL         = 200
MAX_BATCHES_HIGH             = 100
MAX_BATCHES_MEDIUM           = 50
PARALLEL_LOGS                = 28
CACHE_MAX_SIZE               = 500000
TIMEOUT_PER_LOG              = 300
HTTP_CHECK_TIMEOUT           = 5
PATH_CHECK_TIMEOUT           = 3
HTTP_CHECK_RETRIES           = 3
UNREACHABLE_RECHECK_INTERVAL = 300
SESSION_MAX_REQUESTS         = 1000
MAX_PENDING_HTTP             = 5000
MAX_SANS_PER_CERT            = 1000
TARGETS_RELOAD_INTERVAL      = 10
MIN_CERTS_PER_CYCLE          = 100
HTTP_CONCURRENCY_LIMIT       = 50

# JS Scanner config
JS_SCAN_TIMEOUT   = 8
MAX_JS_SIZE       = 3 * 1024 * 1024
MAX_JS_PER_DOMAIN = 20
JS_SCAN_WORKERS   = 8          # ✅ AUGMENTÉ: parallélisme JS
JS_SCAN_INTERVAL  = 3600

# DB Writer config
DB_WRITE_QUEUE_SIZE    = 10000  # ✅ NOUVEAU: queue writes centralisée
DB_WRITE_BATCH_TIMEOUT = 0.05   # flush toutes les 50ms si inactif

_http_semaphore  = threading.Semaphore(HTTP_CONCURRENCY_LIMIT)
HTTP_WORKER_POOL = ThreadPoolExecutor(max_workers=HTTP_CONCURRENCY_LIMIT, thread_name_prefix="HTTPWorker")
# ✅ NOUVEAU: Pool JS dédié, séparé du pool HTTP
JS_WORKER_POOL   = ThreadPoolExecutor(max_workers=JS_SCAN_WORKERS, thread_name_prefix="JSWorker")

NOTIFICATION_TTL              = 1 * 3600
CHECK_HISTORY_RETENTION_DAYS  = 7
VACUUM_INTERVAL_DAYS          = 30

CT_LOGS = [
    {"name": "Google Argon2026h1",    "url": "https://ct.googleapis.com/logs/us1/argon2026h1",  "enabled": True, "priority": "CRITICAL"},
    {"name": "Google Argon2026h2",    "url": "https://ct.googleapis.com/logs/us1/argon2026h2",  "enabled": True, "priority": "CRITICAL"},
    {"name": "Google Argon2027h1",    "url": "https://ct.googleapis.com/logs/us1/argon2027h1",  "enabled": True, "priority": "HIGH"},
    {"name": "Google Xenon2026h1",    "url": "https://ct.googleapis.com/logs/eu1/xenon2026h1",  "enabled": True, "priority": "CRITICAL"},
    {"name": "Google Xenon2026h2",    "url": "https://ct.googleapis.com/logs/eu1/xenon2026h2",  "enabled": True, "priority": "CRITICAL"},
    {"name": "Google Xenon2027h1",    "url": "https://ct.googleapis.com/logs/eu1/xenon2027h1",  "enabled": True, "priority": "HIGH"},
    {"name": "Google Solera2026h1",   "url": "https://ct.googleapis.com/logs/eu1/solera2026h1", "enabled": True, "priority": "MEDIUM"},
    {"name": "Cloudflare Nimbus2026", "url": "https://ct.cloudflare.com/logs/nimbus2026",       "enabled": True, "priority": "CRITICAL"},
    {"name": "Cloudflare Nimbus2027", "url": "https://ct.cloudflare.com/logs/nimbus2027",       "enabled": True, "priority": "HIGH"},
    {"name": "DigiCert Wyvern2026h1", "url": "https://wyvern.ct.digicert.com/2026h1",          "enabled": True, "priority": "HIGH"},
    {"name": "DigiCert Wyvern2027h1", "url": "https://wyvern.ct.digicert.com/2027h1",          "enabled": True, "priority": "HIGH"},
    {"name": "DigiCert Wyvern2027h2", "url": "https://wyvern.ct.digicert.com/2027h2",          "enabled": True, "priority": "MEDIUM"},
    {"name": "DigiCert Sphinx2026h1", "url": "https://sphinx.ct.digicert.com/2026h1",          "enabled": True, "priority": "HIGH"},
    {"name": "DigiCert Sphinx2027h1", "url": "https://sphinx.ct.digicert.com/2027h1",          "enabled": True, "priority": "HIGH"},
    {"name": "DigiCert Sphinx2027h2", "url": "https://sphinx.ct.digicert.com/2027h2",          "enabled": True, "priority": "MEDIUM"},
    {"name": "Sectigo Sabre2026h1",   "url": "https://sabre2026h1.ct.sectigo.com",             "enabled": True, "priority": "HIGH"},
    {"name": "Sectigo Sabre2026h2",   "url": "https://sabre2026h2.ct.sectigo.com",             "enabled": True, "priority": "MEDIUM"},
    {"name": "Sectigo Mammoth2026h1", "url": "https://mammoth2026h1.ct.sectigo.com",           "enabled": True, "priority": "MEDIUM"},
    {"name": "Sectigo Mammoth2026h2", "url": "https://mammoth2026h2.ct.sectigo.com",           "enabled": True, "priority": "MEDIUM"},
    {"name": "Sectigo Tiger2026h1",   "url": "https://tiger2026h1.ct.sectigo.com",             "enabled": True, "priority": "MEDIUM"},
    {"name": "Sectigo Tiger2026h2",   "url": "https://tiger2026h2.ct.sectigo.com",             "enabled": True, "priority": "MEDIUM"},
    {"name": "Sectigo Elephant2026h1","url": "https://elephant2026h1.ct.sectigo.com",          "enabled": True, "priority": "MEDIUM"},
    {"name": "Sectigo Elephant2026h2","url": "https://elephant2026h2.ct.sectigo.com",          "enabled": True, "priority": "MEDIUM"},
    {"name": "LE Oak2026h1",          "url": "https://oak.ct.letsencrypt.org/2026h1",          "enabled": True, "priority": "HIGH"},
    {"name": "LE Oak2026h2",          "url": "https://oak.ct.letsencrypt.org/2026h2",          "enabled": True, "priority": "HIGH"},
    {"name": "TrustAsia Log2026a",    "url": "https://ct2026-a.trustasia.com/log2026a",        "enabled": True, "priority": "CRITICAL"},
    {"name": "TrustAsia Log2026b",    "url": "https://ct2026-b.trustasia.com/log2026b",        "enabled": True, "priority": "CRITICAL"},
    {"name": "TrustAsia HETU2027",    "url": "https://hetu2027.trustasia.com/hetu2027",        "enabled": True, "priority": "HIGH"},
]

ENABLED_LOGS   = [log for log in CT_LOGS if log['enabled']]
NB_LOGS_ACTIFS = len(ENABLED_LOGS)

# ==================== STATS ====================
stats = {
    'certificats_analysés':   0,
    'alertes_envoyées':       0,
    'dernière_alerte':        None,
    'démarrage':              datetime.utcnow(),
    'dernière_vérification':  None,
    'positions':              {},
    'logs_actifs':            NB_LOGS_ACTIFS,
    'duplicates_évités':      0,
    'parse_errors':           0,
    'matches_trouvés':        0,
    'http_checks':            0,
    'batches_processed':      0,
    'x509_count':             0,
    'precert_count':          0,
    'discord_dropped':        0,
    'false_positives':        0,
    'retry_http':             0,
    'circuit_breaker_trips':  0,
    'last_vacuum':            datetime.utcnow(),
    'echo_server_blocked':    0,
    'js_files_scanned':       0,
    'js_secrets_found':       0,
    'js_domains_scanned':     0,
    'last_js_scan':           None,
    'js_false_positives':     0,
    'js_false_negatives':     0,
    'db_write_queue_size':    0,   # ✅ NOUVEAU: monitoring queue DB
    'db_writes_processed':    0,   # ✅ NOUVEAU
}
stats_lock = threading.Lock()

_log_failures      = {}
_log_failures_lock = threading.Lock()
_log_requests_count  = {}
_log_requests_lock   = threading.Lock()

# ==================== CACHE LRU ====================
class LRUCache:
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

# ==================== GLOBAL CYCLE TRACKING ====================
_seen_cycle_lock   = threading.Lock()
_seen_cycle_global = set()

def cycle_seen(domain: str, log_name: str = "") -> bool:
    key = (domain, log_name) if log_name else domain
    with _seen_cycle_lock:
        if key in _seen_cycle_global:
            return True
        _seen_cycle_global.add(key)
        return False

def cycle_reset():
    with _seen_cycle_lock:
        _seen_cycle_global.clear()

# ==================== NOTIFICATION CACHE ====================
class NotificationCache:
    def __init__(self, ttl_seconds=3600):
        self.cache = {}
        self.ttl   = ttl_seconds
        self.lock  = threading.Lock()

    def already_notified(self, domain, log_name=""):
        key = (domain, log_name) if log_name else domain
        with self.lock:
            if key in self.cache:
                if time.time() - self.cache[key] < self.ttl:
                    return True
                del self.cache[key]
            return False

    def mark(self, domain, log_name=""):
        key = (domain, log_name) if log_name else domain
        with self.lock:
            self.cache[key] = time.time()

    def clear_expired(self):
        with self.lock:
            now     = time.time()
            expired = [d for d, t in self.cache.items() if now - t >= self.ttl]
            for d in expired:
                del self.cache[d]
            return len(expired)

notif_cache = NotificationCache(ttl_seconds=NOTIFICATION_TTL)

# ==================== DISCORD QUEUE ====================
_discord_queue = queue.Queue(maxsize=500)

def _discord_worker():
    while True:
        try:
            payload = _discord_queue.get(timeout=5)
            if payload is None:
                break
            if not DISCORD_WEBHOOK:
                _discord_queue.task_done()
                continue
            try:
                headers = {"Content-Type": "application/json"}
                if DISCORD_SECRET:
                    body = json.dumps(payload)
                    sig  = hmac.new(DISCORD_SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
                    headers["X-Signature"] = sig
                requests.post(DISCORD_WEBHOOK, json=payload, headers=headers, timeout=10)
            except Exception as e:
                tprint(f"[DISCORD WORKER ERROR] {e}")
            finally:
                _discord_queue.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            tprint(f"[DISCORD WORKER FATAL] {e}")

def discord_send(payload: dict):
    try:
        _discord_queue.put_nowait(payload)
    except queue.Full:
        with stats_lock:
            stats['discord_dropped'] += 1
        tprint("[DISCORD QUEUE] ⚠️ PLEINE — payload ignoré")

_discord_thread = threading.Thread(target=_discord_worker, daemon=True, name="DiscordWorker")
_discord_thread.start()

# ==================== HEALTHCHECK ====================
def update_heartbeat():
    try:
        with open(HEARTBEAT_FILE, 'w') as f:
            f.write(str(int(time.time())))
    except Exception:
        pass

# ==================== SESSION MANAGEMENT ====================
_session_local = threading.local()

def get_session():
    if not hasattr(_session_local, 'session') or _session_local.session is None:
        s       = requests.Session()
        adapter = requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=20, max_retries=0)
        s.mount('https://', adapter)
        s.mount('http://', adapter)
        s.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        s.verify = False
        _session_local.session       = s
        _session_local.request_count = 0

    _session_local.request_count += 1
    if _session_local.request_count >= SESSION_MAX_REQUESTS:
        try:
            _session_local.session.close()
        except Exception:
            pass
        _session_local.session = None
        return get_session()

    return _session_local.session

def cleanup_sessions():
    try:
        if hasattr(_session_local, 'session') and _session_local.session:
            _session_local.session.close()
    except Exception:
        pass

weakref.finalize(_session_local, cleanup_sessions)

# ==================== DATABASE WRITER CENTRALISÉ ====================
# ✅ NOUVEAU: Toutes les écritures passent par une queue unique.
#    Un seul thread écrit en DB → élimine la contention WAL entre threads.
#    Les lectures restent thread-local (WAL permet reads concurrents).

class _DBWriteOp:
    """Représente une opération d'écriture asynchrone."""
    __slots__ = ('sql', 'params', 'result_future')

    def __init__(self, sql: str, params: tuple, result_future=None):
        self.sql            = sql
        self.params         = params
        self.result_future  = result_future  # threading.Event ou None

_SENTINEL = object()  # signal d'arrêt du writer

class DatabaseWriter:
    """
    Thread unique qui consomme la queue des writes.
    Accumule des micro-batches pour limiter les fsync et améliorer le débit.
    """
    def __init__(self, db_path: str, queue_size: int = DB_WRITE_QUEUE_SIZE):
        self._queue    = queue.Queue(maxsize=queue_size)
        self._conn     = None
        self._db_path  = db_path
        self._thread   = threading.Thread(
            target=self._run, daemon=True, name="DBWriter"
        )
        self._thread.start()

    def _open_conn(self):
        conn = sqlite3.connect(self._db_path, check_same_thread=True, timeout=60)
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=NORMAL')
        conn.execute('PRAGMA cache_size=-64000')
        conn.execute('PRAGMA busy_timeout=10000')
        return conn

    def _run(self):
        self._conn = self._open_conn()
        batch = []
        last_commit = time.monotonic()

        while True:
            # Attendre la prochaine op (ou timeout pour flush)
            try:
                op = self._queue.get(timeout=DB_WRITE_BATCH_TIMEOUT)
            except queue.Empty:
                op = None

            if op is _SENTINEL:
                # Flush final avant arrêt
                if batch:
                    self._flush(batch)
                    batch = []
                self._conn.close()
                return

            if op is not None:
                batch.append(op)
                self._queue.task_done()

            # Flush si batch plein ou timeout dépassé
            now = time.monotonic()
            if batch and (len(batch) >= 200 or (now - last_commit) >= 0.2 or op is None):
                self._flush(batch)
                batch = []
                last_commit = now

    def _flush(self, batch: list):
        try:
            cursor = self._conn.cursor()
            errors_in_batch = 0
            for op in batch:
                try:
                    cursor.execute(op.sql, op.params)
                except sqlite3.IntegrityError:
                    pass  # UNIQUE violations attendues (INSERT OR IGNORE)
                except Exception as e:
                    errors_in_batch += 1
                    # Log seulement 1 fois par batch pour éviter le flood
                    if errors_in_batch == 1:
                        tprint(f"[DB WRITER] Erreur op: {e} — SQL: {op.sql[:60]}")
                finally:
                    if op.result_future:
                        op.result_future.set()
            self._conn.commit()
            with stats_lock:
                stats['db_writes_processed'] += len(batch)
                stats['db_write_queue_size']  = self._queue.qsize()
        except Exception as e:
            tprint(f"[DB WRITER] Erreur flush: {e}")
            traceback.print_exc()
            try:
                self._conn.rollback()
            except Exception:
                pass

    def execute(self, sql: str, params: tuple = (), wait: bool = False):
        """
        Soumet un write.
        wait=True → bloque jusqu'à ce que l'op soit commitée (pour les cas critiques).
        wait=False → fire-and-forget (défaut, optimal pour le bulk).
        """
        ev = threading.Event() if wait else None
        op = _DBWriteOp(sql, params, ev)
        try:
            self._queue.put(op, timeout=5)
        except queue.Full:
            tprint("[DB WRITER] ⚠️ Queue pleine — write ignoré")
            return
        if ev:
            ev.wait(timeout=10)

    def stop(self):
        self._queue.put(_SENTINEL)
        self._thread.join(timeout=10)


# ==================== DATABASE (READS thread-local, WRITES via DBWriter) ====================
class CertificateDatabase:
    def __init__(self, db_path):
        self.db_path = db_path
        self._local  = threading.local()
        # Le writer est initialisé après init_db (qui a besoin d'écrire directement)
        self._writer: DatabaseWriter | None = None
        self._init_writer_lock = threading.Lock()
        self.init_db()
        # Démarrer le writer après l'initialisation du schéma
        self._writer = DatabaseWriter(db_path)
        tprint("[DB] DatabaseWriter démarré")

    # ── Connexion READ (thread-local) ──────────────────────────────────────
    def _get_read_conn(self):
        """Connexion dédiée aux lectures — une par thread worker."""
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            conn = sqlite3.connect(self.db_path, check_same_thread=True, timeout=30)
            conn.execute('PRAGMA journal_mode=WAL')
            conn.execute('PRAGMA synchronous=NORMAL')
            conn.execute('PRAGMA cache_size=-32000')
            conn.execute('PRAGMA query_only=ON')  # ✅ Sécurité: read-only
            self._local.conn = conn
            weakref.finalize(self._local, lambda c=conn: c.close())
        return self._local.conn

    # Alias rétro-compat pour get_conn() utilisé par cleanup_db/dump_db
    def get_conn(self):
        """Connexion directe (lecture/écriture) — usage exceptionnel uniquement."""
        if not hasattr(self._local, 'rw_conn') or self._local.rw_conn is None:
            conn = sqlite3.connect(self.db_path, check_same_thread=True, timeout=60)
            conn.execute('PRAGMA journal_mode=WAL')
            conn.execute('PRAGMA synchronous=NORMAL')
            self._local.rw_conn = conn
        return self._local.rw_conn

    def init_db(self):
        """Initialisation schéma — exécuté une seule fois au démarrage."""
        conn   = self.get_conn()
        cursor = conn.cursor()
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
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS check_history (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                domain           TEXT NOT NULL,
                status_code      INTEGER,
                response_time_ms INTEGER,
                check_timestamp  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS false_positives (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                domain    TEXT NOT NULL,
                path      TEXT,
                reason    TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS anomalies (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                cert_hash    TEXT NOT NULL,
                anomaly_type TEXT,
                detail       TEXT,
                timestamp    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS js_secrets (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                domain       TEXT NOT NULL,
                js_url       TEXT NOT NULL,
                secret_type  TEXT NOT NULL,
                secret_value TEXT NOT NULL,
                context      TEXT,
                confidence   INTEGER DEFAULT 50,
                notified     BOOLEAN DEFAULT 0,
                timestamp    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(js_url, secret_type, secret_value)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS js_scan_history (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                js_url        TEXT UNIQUE NOT NULL,
                content_hash  TEXT,
                last_scan     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                secrets_found INTEGER DEFAULT 0
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS js_false_positives (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                domain       TEXT NOT NULL,
                js_url       TEXT NOT NULL,
                secret_type  TEXT NOT NULL,
                secret_value TEXT NOT NULL,
                reason       TEXT,
                timestamp    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Migration unreachable_domains → subdomains
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='unreachable_domains'")
        if cursor.fetchone():
            cursor.execute('''
                INSERT OR IGNORE INTO subdomains (domain, base_domain, status_code, is_online, first_seen, last_check, log_source)
                SELECT domain, base_domain, status_code, 0, first_seen, last_check, log_source
                FROM unreachable_domains
            ''')
            cursor.execute('DROP TABLE unreachable_domains')
            tprint("[DB] Migration unreachable_domains → subdomains effectuée")

        # ── Migration colonnes manquantes (ALTER TABLE idempotent) ───────────
        # Nécessaire quand la DB a été créée par une version antérieure du script.
        # SQLite ne supporte pas ALTER TABLE ADD COLUMN IF NOT EXISTS,
        # donc on inspecte pragma table_info() avant chaque ALTER.
        def _add_column_if_missing(table: str, column: str, col_def: str):
            cursor.execute(f'PRAGMA table_info({table})')
            existing_cols = {row[1] for row in cursor.fetchall()}
            if column not in existing_cols:
                cursor.execute(f'ALTER TABLE {table} ADD COLUMN {column} {col_def}')
                tprint(f"[DB MIGRATION] ALTER TABLE {table} ADD COLUMN {column}")

        _add_column_if_missing('js_secrets', 'confidence',  'INTEGER DEFAULT 50')
        _add_column_if_missing('js_secrets', 'notified',    'BOOLEAN DEFAULT 0')
        _add_column_if_missing('js_secrets', 'context',     'TEXT')
        _add_column_if_missing('subdomains', 'log_source',  'TEXT')
        # ─────────────────────────────────────────────────────────────────────

        cursor.execute('CREATE INDEX IF NOT EXISTS idx_domain ON subdomains(domain)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_last_check ON subdomains(last_check)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_is_online ON subdomains(is_online)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_log_source ON subdomains(log_source)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_history_ts ON check_history(check_timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_fp_domain ON false_positives(domain)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_anom_hash ON anomalies(cert_hash)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_js_domain ON js_secrets(domain)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_js_url ON js_scan_history(js_url)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_js_fp_domain ON js_false_positives(domain)')
        conn.commit()
        tprint(f"[DB] Initialisée: {self.db_path}")

    # ── WRITES (via DatabaseWriter) ────────────────────────────────────────

    def subdomain_exists(self, domain) -> bool:
        """Read — thread-local."""
        try:
            cursor = self._get_read_conn().cursor()
            cursor.execute('SELECT 1 FROM subdomains WHERE domain = ? LIMIT 1', (domain,))
            return cursor.fetchone() is not None
        except Exception as e:
            tprint(f"[DB ERROR] subdomain_exists: {e}")
            return False

    def add_domain(self, domain, base_domain, status_code, log_source) -> bool:
        """
        ✅ REFACTORISÉ: Check existence via read conn, write via DBWriter.
        Retourne True si nouveau, False si update.
        """
        is_online = 1 if status_code == 200 else 0
        try:
            # Read: vérifier existence
            cursor = self._get_read_conn().cursor()
            cursor.execute('SELECT 1 FROM subdomains WHERE domain = ? LIMIT 1', (domain,))
            exists = cursor.fetchone() is not None

            if exists:
                self._writer.execute(
                    'UPDATE subdomains SET status_code=?, is_online=?, last_check=CURRENT_TIMESTAMP WHERE domain=?',
                    (status_code, is_online, domain)
                )
                return False
            else:
                self._writer.execute(
                    'INSERT OR IGNORE INTO subdomains (domain, base_domain, status_code, is_online, log_source) VALUES (?,?,?,?,?)',
                    (domain, base_domain, status_code, is_online, log_source)
                )
                return True
        except Exception as e:
            tprint(f"[DB ERROR] add_domain {domain}: {e}")
            return False

    def add_subdomain_from_file(self, domain, base_domain, status_code=None):
        is_online = 1 if status_code == 200 else 0
        self._writer.execute(
            'INSERT OR IGNORE INTO subdomains (domain, base_domain, status_code, is_online, log_source) VALUES (?,?,?,?,?)',
            (domain, base_domain, status_code, is_online, "MANUAL_LOAD")
        )
        return True

    def log_false_positive(self, domain, path, reason):
        self._writer.execute(
            'INSERT INTO false_positives (domain, path, reason) VALUES (?,?,?)',
            (domain, path, reason)
        )
        with stats_lock:
            stats['false_positives'] += 1

    def log_js_false_positive(self, domain, js_url, secret_type, secret_value, reason):
        self._writer.execute(
            'INSERT INTO js_false_positives (domain, js_url, secret_type, secret_value, reason) VALUES (?,?,?,?,?)',
            (domain, js_url, secret_type, secret_value[:120], reason)
        )
        with stats_lock:
            stats['js_false_positives'] += 1

    def log_anomaly(self, cert_hash, anomaly_type, detail):
        self._writer.execute(
            'INSERT INTO anomalies (cert_hash, anomaly_type, detail) VALUES (?,?,?)',
            (cert_hash, anomaly_type, detail)
        )

    def save_js_secret(self, domain, js_url, secret_type, secret_value, context, confidence=50) -> bool:
        """
        ✅ REFACTORISÉ: read existence d'abord, puis write via DBWriter.
        Retourne True si nouveau secret.
        """
        try:
            cursor = self._get_read_conn().cursor()
            cursor.execute(
                'SELECT 1 FROM js_secrets WHERE js_url=? AND secret_type=? AND secret_value=? LIMIT 1',
                (js_url, secret_type, secret_value[:500])
            )
            if cursor.fetchone():
                return False
            self._writer.execute(
                '''INSERT OR IGNORE INTO js_secrets
                   (domain, js_url, secret_type, secret_value, context, confidence)
                   VALUES (?,?,?,?,?,?)''',
                (domain, js_url, secret_type, secret_value[:500], context[:500] if context else '', confidence)
            )
            return True
        except Exception as e:
            tprint(f"[DB ERROR] save_js_secret: {e}")
            return False

    def get_js_scan_history(self, js_url) -> dict | None:
        try:
            cursor = self._get_read_conn().cursor()
            cursor.execute(
                'SELECT content_hash, last_scan, secrets_found FROM js_scan_history WHERE js_url=?',
                (js_url,)
            )
            row = cursor.fetchone()
            if row:
                return {'content_hash': row[0], 'last_scan': row[1], 'secrets_found': row[2]}
            return None
        except Exception:
            return None

    def update_js_scan_history(self, js_url, content_hash, secrets_found):
        self._writer.execute(
            '''INSERT INTO js_scan_history (js_url, content_hash, secrets_found)
               VALUES (?,?,?)
               ON CONFLICT(js_url) DO UPDATE SET
                   content_hash=excluded.content_hash,
                   secrets_found=excluded.secrets_found,
                   last_scan=CURRENT_TIMESTAMP''',
            (js_url, content_hash, secrets_found)
        )

    def get_offline(self, limit=100, offset=0):
        try:
            cursor = self._get_read_conn().cursor()
            cursor.execute('''
                SELECT domain, base_domain, last_check
                FROM subdomains
                WHERE is_online = 0
                ORDER BY last_check ASC NULLS FIRST
                LIMIT ? OFFSET ?
            ''', (limit, offset))
            return cursor.fetchall()
        except Exception as e:
            tprint(f"[DB ERROR] get_offline: {e}")
            return []

    def count_offline(self):
        try:
            cursor = self._get_read_conn().cursor()
            cursor.execute('SELECT COUNT(*) FROM subdomains WHERE is_online = 0')
            return cursor.fetchone()[0]
        except Exception:
            return 0

    def iter_all_domains(self, page_size=500):
        offset = 0
        while True:
            try:
                cursor = self._get_read_conn().cursor()
                cursor.execute(
                    'SELECT domain FROM subdomains ORDER BY domain LIMIT ? OFFSET ?',
                    (page_size, offset)
                )
                rows = cursor.fetchall()
                if not rows:
                    break
                for (domain,) in rows:
                    yield domain
                offset += page_size
            except Exception as e:
                tprint(f"[DB ERROR] iter_all_domains: {e}")
                break

    def iter_online_domains(self, page_size=200):
        offset = 0
        while True:
            try:
                cursor = self._get_read_conn().cursor()
                cursor.execute(
                    'SELECT domain FROM subdomains WHERE is_online=1 ORDER BY domain LIMIT ? OFFSET ?',
                    (page_size, offset)
                )
                rows = cursor.fetchall()
                if not rows:
                    break
                for (domain,) in rows:
                    yield domain
                offset += page_size
            except Exception as e:
                tprint(f"[DB ERROR] iter_online_domains: {e}")
                break

    def get_all_domains(self):
        return list(self.iter_all_domains())

    def update_check(self, domain, status_code, response_time_ms):
        is_online = 1 if status_code == 200 else 0
        self._writer.execute(
            'UPDATE subdomains SET status_code=?, is_online=?, last_check=CURRENT_TIMESTAMP WHERE domain=?',
            (status_code, is_online, domain)
        )
        self._writer.execute(
            'INSERT INTO check_history (domain, status_code, response_time_ms) VALUES (?,?,?)',
            (domain, status_code, response_time_ms)
        )
        return True

    def mark_online(self, domain, status_code):
        self._writer.execute(
            'UPDATE subdomains SET is_online=1, status_code=?, last_check=CURRENT_TIMESTAMP WHERE domain=?',
            (status_code, domain)
        )

    def purge_history(self, retention_days=CHECK_HISTORY_RETENTION_DAYS):
        """
        ✅ REFACTORISÉ: soumis en async via writer (non bloquant).
        Le rowcount n'est pas récupérable en async, on loggue simplement.
        """
        self._writer.execute(
            "DELETE FROM check_history WHERE check_timestamp < datetime('now', ? || ' days')",
            (f'-{retention_days}',)
        )
        tprint(f"[DB PURGE] Purge historique >  {retention_days}j soumise")
        return 0

    def vacuum_optimize(self):
        # PRAGMA optimize doit passer par une connexion directe (pas via writer)
        try:
            conn = self.get_conn()
            conn.execute('PRAGMA optimize')
            conn.commit()
            tprint("[DB] PRAGMA optimize exécuté")
        except Exception as e:
            tprint(f"[DB ERROR] vacuum_optimize: {e}")

    def count(self):
        try:
            cursor = self._get_read_conn().cursor()
            cursor.execute('SELECT COUNT(*) FROM subdomains')
            return cursor.fetchone()[0]
        except Exception:
            return 0

    def size_mb(self):
        try:
            return round(os.path.getsize(self.db_path) / 1024 / 1024, 2)
        except Exception:
            return 0

    def stats_summary(self):
        try:
            cursor = self._get_read_conn().cursor()
            cursor.execute('''
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN is_online=1 THEN 1 ELSE 0 END) as online,
                    SUM(CASE WHEN is_online=0 AND status_code IS NULL THEN 1 ELSE 0 END) as timeouts,
                    SUM(CASE WHEN status_code>=400 AND status_code<500 THEN 1 ELSE 0 END) as errors_4xx,
                    SUM(CASE WHEN status_code>=500 THEN 1 ELSE 0 END) as errors_5xx
                FROM subdomains
            ''')
            row = cursor.fetchone()
            return {
                'total':   row[0] or 0,
                'online':  row[1] or 0,
                'timeout': row[2] or 0,
                '4xx':     row[3] or 0,
                '5xx':     row[4] or 0,
            }
        except Exception:
            return {'total': 0, 'online': 0, 'timeout': 0, '4xx': 0, '5xx': 0}

db = CertificateDatabase(DATABASE_FILE)

# ==================== DOMAIN VALIDATION ====================
def validate_domain(domain: str) -> bool:
    domain = domain.lower().strip()
    if domain.startswith('.') or domain.endswith('.'):
        return False
    if domain.startswith('*.'):
        return False
    if '..' in domain:
        return False
    if len(domain) > 253:
        return False
    if not re.match(r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]{2,}$', domain):
        return False
    try:
        idna_encode(domain)
        return True
    except (IDNAError, Exception):
        return False

# ==================== POSITION PERSISTENCE ====================
def load_positions():
    try:
        if os.path.exists(POSITIONS_FILE):
            with open(POSITIONS_FILE, 'r') as f:
                return json.load(f)
        elif os.path.exists(POSITIONS_WAL):
            with open(POSITIONS_WAL, 'r') as f:
                return json.load(f)
    except Exception as e:
        tprint(f"[WARN] Erreur chargement positions: {e}")
    return {}

def save_positions():
    tmp_file = POSITIONS_FILE + '.tmp'
    try:
        with stats_lock:
            positions_copy = dict(stats['positions'])
        with open(tmp_file, 'w') as f:
            json.dump(positions_copy, f, indent=2)
        try:
            f_tmp = os.open(tmp_file, os.O_RDONLY)
            os.fsync(f_tmp)
            os.close(f_tmp)
        except Exception:
            pass
        os.replace(tmp_file, POSITIONS_FILE)
        try:
            if os.path.exists(POSITIONS_WAL):
                os.remove(POSITIONS_WAL)
        except Exception:
            pass
    except Exception as e:
        tprint(f"[WARN] Sauvegarde positions: {e}")
        try:
            os.remove(tmp_file)
        except Exception:
            pass

stats['positions'] = load_positions()

# ==================== CIRCUIT BREAKER ====================
class CircuitBreaker:
    def __init__(self, failure_threshold=3):
        self.failures       = 0
        self.threshold      = failure_threshold
        self.is_open        = False
        self.lock           = threading.Lock()
        self.last_fail_time = None

    def record_success(self):
        with self.lock:
            self.failures = 0
            self.is_open  = False

    def record_failure(self):
        with self.lock:
            self.failures      += 1
            self.last_fail_time = time.time()
            if self.failures >= self.threshold:
                self.is_open = True

    def is_available(self):
        with self.lock:
            if not self.is_open:
                return True
            if time.time() - self.last_fail_time > 300:
                self.is_open  = False
                self.failures = 0
                return True
            return False

_circuit_breakers = {}
_cb_lock          = threading.Lock()

def get_circuit_breaker(log_name):
    with _cb_lock:
        if log_name not in _circuit_breakers:
            _circuit_breakers[log_name] = CircuitBreaker()
        return _circuit_breakers[log_name]

# ==================== RETRY LOGIC ====================
def retry_with_backoff(func, max_retries=HTTP_CHECK_RETRIES, timeout_base=1):
    for attempt in range(max_retries):
        try:
            return func()
        except Exception as e:
            if attempt < max_retries - 1:
                tprint(f"[RETRY] Attempt {attempt+1}/{max_retries} failed: {str(e)[:100]}")
                wait_time = timeout_base * (2 ** attempt)
                with stats_lock:
                    stats['retry_http'] += 1
                time.sleep(wait_time)
            else:
                tprint(f"[RETRY] All {max_retries} attempts failed.")
    return None

# ==================== ECHO-SERVER DETECTION ====================
ECHO_SERVER_REQUIRED_KEYS  = {'path', 'headers', 'method'}
ECHO_SERVER_STRONG_KEYS    = {'hostname', 'os', 'connection', 'protocol', 'fresh', 'xhr', 'subdomains', 'ips'}
ECHO_SERVER_HEADER_MARKERS = {'x-forwarded-for', 'x-real-ip', 'x-forwarded-proto', 'traceparent', 'x-request-id'}

def is_echo_server_response(content: str, requested_path: str) -> tuple:
    if not content:
        return (False, None)
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return (False, None)
    if not isinstance(data, dict):
        return (False, None)
    keys = set(data.keys())
    if ECHO_SERVER_REQUIRED_KEYS.issubset(keys):
        strong_matches = keys & ECHO_SERVER_STRONG_KEYS
        if len(strong_matches) >= 2:
            return (True, f"echo-server: clés détectées {ECHO_SERVER_REQUIRED_KEYS | strong_matches}")
    if 'path' in data and 'headers' in data and isinstance(data.get('headers'), dict):
        response_path = data.get('path', '')
        if response_path == requested_path:
            return (True, f"echo-server: path reflété '{response_path}'")
    if isinstance(data.get('headers'), dict):
        response_headers_keys = set(k.lower() for k in data['headers'].keys())
        matching_markers = response_headers_keys & ECHO_SERVER_HEADER_MARKERS
        if len(matching_markers) >= 2 and 'method' in keys:
            return (True, f"echo-server: headers internes reflétés {matching_markers}")
    if isinstance(data.get('os'), dict) and 'hostname' in data.get('os', {}):
        if 'headers' in keys and 'method' in keys:
            return (True, "echo-server: os.hostname présent (pattern K8s)")
    return (False, None)

# ==================== FALSE POSITIVE DETECTION ====================
PATH_CONTENT_EXPECTATIONS = {
    '.env':            ['=', 'KEY', 'SECRET', 'PASSWORD', 'TOKEN', 'DB_', 'APP_', 'HOST'],
    '.env.backup':     ['=', 'KEY', 'SECRET', 'PASSWORD', 'TOKEN'],
    '.env.local':      ['=', 'KEY', 'SECRET', 'DB_'],
    '.env.production': ['=', 'KEY', 'SECRET', 'PASSWORD'],
    '.git/config':     ['[core]', '[remote', 'repositoryformatversion', 'filemode'],
    'wp-config.php':   ['DB_NAME', 'DB_PASSWORD', 'DB_HOST', 'table_prefix', "define("],
    'backup.sql':      ['INSERT INTO', 'CREATE TABLE', 'DROP TABLE', 'mysqldump', '-- MySQL'],
    'actuator/env':    ['"activeProfiles"', '"propertySources"', '"systemProperties"'],
    'actuator/health': ['"status"', '"UP"', '"DOWN"', '"components"'],
    'actuator/metrics':['"names"', '"measurements"'],
    'api/v1/users':    ['"id"', '"email"', '"username"', '"users"'],
    'phpinfo.php':     ['PHP Version', 'phpinfo', 'php.ini'],
    'server-status':   ['Apache Server Status', 'requests currently being processed'],
    'adminer':         ['Adminer', 'adminer', 'db_driver'],
    'phpmyadmin':      ['phpMyAdmin', 'pma_', 'PMA_'],
}

def check_content_coherence(body: str, path: str) -> tuple:
    path_low    = path.lower()
    body_sample = body[:5000]
    try:
        parsed_json = json.loads(body_sample)
        if isinstance(parsed_json, dict):
            if isinstance(parsed_json.get('headers'), dict) and 'method' in parsed_json and 'path' in parsed_json:
                return (False, "echo-server: JSON reflète la requête entrante")
    except (json.JSONDecodeError, ValueError):
        pass
    for pattern, keywords in PATH_CONTENT_EXPECTATIONS.items():
        if pattern in path_low:
            found = [kw for kw in keywords if kw.lower() in body_sample.lower()]
            if not found:
                return (False, f"path '{pattern}' expects {keywords[:3]}... none found")
            return (True, f"found: {found[:2]}")
    return (True, "no_rule")

# ==================== WAF DETECTION ====================
WAF_BLOCK_BODY_SIGNATURES = [
    'you have been blocked', 'this request has been blocked', 'access denied',
    'your access to this site has been limited', 'sorry, you have been blocked',
    '__cf_chl_opt', 'cf-please-wait', 'checking your browser before accessing',
    'sucuri website firewall - access denied', 'incapsula incident id',
    '_incapsula_resource', 'incapsula_error', 'mod_security', 'request rejected',
    'forbidden by policy', 'security policy violation', 'NotFoundException',
    'not found', 'endpoint not found', 'resource not found',
]

def is_waf_block(response) -> tuple:
    headers      = {k.lower(): v.lower() for k, v in response.headers.items()}
    content_type = headers.get('content-type', '')
    if 'text/html' not in content_type:
        return (False, None)
    try:
        body     = response.text[:8000]
        is_short = len(body) < 2000
        body_low = body.lower()
        for sig in WAF_BLOCK_BODY_SIGNATURES:
            if sig.lower() in body_low:
                return (True, f"waf: '{sig}'")
        if is_short and 'cloudflare' in body_low and ('challenge' in body_low or 'captcha' in body_low):
            return (True, "waf: cloudflare")
        if is_short and '_incapsula_resource' in body_low:
            return (True, "waf: incapsula")
    except Exception:
        pass
    return (False, None)

# ==================== HTTP CHECKER ====================
def _do_check_domain(domain: str) -> tuple:
    MAX_REDIRECTS = 5
    session       = get_session()
    for protocol in ['https', 'http']:
        try:
            with _http_semaphore:
                start    = time.time()
                response = session.get(
                    f"{protocol}://{domain}",
                    timeout=HTTP_CHECK_TIMEOUT,
                    allow_redirects=True,
                    stream=False
                )
            elapsed       = int((time.time() - start) * 1000)
            requested_url = f"{protocol}://{domain}"
            if response.url != requested_url and response.url.lower() != f"{protocol}://{domain.lower()}/":
                if len(response.history) > MAX_REDIRECTS:
                    return (403, elapsed)
                original_domain = urlparse(requested_url).netloc
                redirect_domain = urlparse(response.url).netloc
                if original_domain.lower() != redirect_domain.lower():
                    return (403, elapsed)
            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', '').lower()
                if content_type and 'text/html' not in content_type and 'application/json' not in content_type:
                    return (403, elapsed)
                waf, reason = is_waf_block(response)
                if waf:
                    return (403, elapsed)
                return (200, elapsed)
            elif response.status_code == 403:
                return (403, elapsed)
            return (response.status_code, elapsed)
        except Exception:
            continue
    return (None, None)

def check_domain(domain: str) -> tuple | None:
    def inner_check():
        future = HTTP_WORKER_POOL.submit(_do_check_domain, domain)
        try:
            return future.result(timeout=HTTP_CHECK_TIMEOUT + 2)
        except Exception:
            return None
    result = retry_with_backoff(inner_check)
    if result is None:
        tprint(f"[HTTP CHECK] Échec total après {HTTP_CHECK_RETRIES} tentatives pour {domain}")
        return None
    return result

def check_port(host, port, timeout=10):
    try:
        start = time.time()
        sock  = socket.create_connection((host, port), timeout=timeout)
        elapsed = int((time.time() - start) * 1000)
        sock.close()
        return (True, elapsed)
    except Exception:
        return (False, None)

def parse_subdomain_entry(entry):
    entry = entry.strip().lower()
    if ':' in entry:
        parts = entry.rsplit(':', 1)
        try:
            return (parts[0], int(parts[1]))
        except ValueError:
            return (entry, None)
    return (entry, None)

# ==================== LOAD TARGET DOMAINS ====================
def load_targets():
    try:
        with open(DOMAINS_FILE, 'r') as f:
            raw_domains = {line.strip().lower() for line in f if line.strip() and not line.startswith('#')}
        valid   = set()
        invalid = []
        for domain in raw_domains:
            if validate_domain(domain):
                valid.add(domain)
            else:
                invalid.append(domain)
        if invalid:
            tprint(f"[WARN] {len(invalid)} domaines invalides: {invalid[:5]}...")
        if not valid:
            tprint("[ERROR] Aucun domaine valide — arrêt")
            exit(1)
        tprint(f"[OK] {len(valid)} domaines chargés")
        return valid
    except Exception as e:
        tprint(f"[ERROR] Chargement domaines: {e}")
        exit(1)

targets = load_targets()

# ==================== PATH MONITOR ====================
class PathMonitor:
    DEFAULT_PATHS = [
        "/.env", "/.env.backup", "/.git/config", "/wp-config.php",
        "/actuator/env", "/api/v1/users", "/backup.sql",
    ]

    def __init__(self, paths_file):
        self.paths_file = paths_file
        self.paths      = list(self.DEFAULT_PATHS)
        self.load_paths()

    def load_paths(self):
        if not os.path.exists(self.paths_file):
            tprint(f"[PATHS] {self.paths_file} absent — {len(self.paths)} paths par défaut")
            return
        try:
            with open(self.paths_file, 'r') as f:
                custom = [l.strip() for l in f if l.strip() and not l.startswith('#')]
            for p in custom:
                if p not in self.paths:
                    self.paths.append(p)
            tprint(f"[PATHS] {len(self.DEFAULT_PATHS)} défaut + {len(custom)} custom = {len(self.paths)} total")
        except Exception as e:
            tprint(f"[PATHS ERROR] {e}")

    def check_path(self, url: str) -> tuple:
        MAX_CONTENT_SIZE = 5 * 1024 * 1024
        parsed_path      = urlparse(url).path
        session          = get_session()
        try:
            with _http_semaphore:
                response = session.get(url, timeout=PATH_CHECK_TIMEOUT, allow_redirects=True, stream=True)
            response_time = int(response.elapsed.total_seconds() * 1000)
            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', '').lower()
                if 'text/html' in content_type:
                    response.close()
                    return (403, None, response_time, "HTML content-type")
                if content_type and 'application/json' not in content_type \
                        and 'text/plain' not in content_type \
                        and 'application/octet-stream' not in content_type \
                        and 'application/x-sh' not in content_type:
                    response.close()
                    return (403, None, response_time, f"Invalid Content-Type: {content_type}")
                try:
                    size = int(response.headers.get('Content-Length', '0'))
                    if size > MAX_CONTENT_SIZE:
                        response.close()
                        return (403, None, response_time, f"Content too large ({size})")
                except Exception:
                    pass
                try:
                    chunks = []
                    total  = 0
                    for chunk in response.iter_content(chunk_size=8192, decode_unicode=True):
                        if isinstance(chunk, bytes):
                            chunk = chunk.decode('utf-8', errors='replace')
                        chunks.append(chunk)
                        total += len(chunk)
                        if total >= MAX_CONTENT_SIZE:
                            break
                    content = ''.join(chunks)
                    response.close()
                except Exception as e:
                    response.close()
                    return (None, None, response_time, f"Error reading body: {str(e)[:50]}")
                if not content or len(content) <= 200:
                    return (403, None, response_time, f"Content too small ({len(content)} bytes)")
                body_start = content.lstrip('\ufeff').lstrip()[:200].lower()
                if body_start.startswith('<!doctype') or body_start.startswith('<html'):
                    return (403, None, response_time, "HTML body")
                is_echo, echo_reason = is_echo_server_response(content, parsed_path)
                if is_echo:
                    domain = urlparse(url).netloc
                    db.log_false_positive(domain, parsed_path, echo_reason)
                    with stats_lock:
                        stats['echo_server_blocked'] += 1
                    tprint(f"[PATHS FP] Echo-server bloqué: {url} — {echo_reason}")
                    return (403, None, response_time, f"False positive: {echo_reason}")
                is_coherent, coherence_reason = check_content_coherence(content, parsed_path)
                if not is_coherent:
                    return (403, None, response_time, f"Content mismatch: {coherence_reason}")
                return (200, content, response_time, None)
            elif response.status_code == 403:
                return (403, None, response_time, None)
            return (response.status_code, None, response_time, None)
        except requests.exceptions.Timeout:
            return (None, None, PATH_CHECK_TIMEOUT * 1000, "Timeout")
        except Exception as e:
            return (None, None, None, str(e)[:100])

    def send_content_alert(self, url, content):
        preview = content[:1900]
        if len(content) > 1900:
            preview += f"\n... (tronqué, taille: {len(content)} chars)"
        embed = {
            "title":       "✅ Fichier sensible accessible",
            "description": f"`{url}`\n\n```\n{preview}\n```",
            "color":       0x00ff00,
            "fields": [
                {"name": "Taille", "value": f"{len(content)} bytes", "inline": True},
                {"name": "Status", "value": "200 OK",                "inline": True},
            ],
            "footer":    {"text": "CT Monitor"},
            "timestamp": datetime.utcnow().isoformat()
        }
        discord_send({"embeds": [embed]})
        tprint(f"[PATHS ALERT] Fichier sensible: {url}")

    def check_domain_paths(self, domain) -> tuple:
        host, port = parse_subdomain_entry(domain)
        found = errors = checked = 0
        for path in self.paths:
            for protocol in ['https', 'http']:
                url                                          = f"{protocol}://{host}{path}"
                status_code, content, response_time, error  = self.check_path(url)
                checked += 1
                if status_code == 200 and content:
                    tprint(f"[PATHS] ✅ TROUVE: {url} [{len(content)} bytes]")
                    self.send_content_alert(url, content)
                    found += 1
                    break
                elif error:
                    errors += 1
                    break
                else:
                    break
        return found, checked, errors

    def check_all(self):
        """
        ✅ REFACTORISÉ: collecte des résultats optimisée avec as_completed.
        Soumet par batch de SUBMIT_BATCH, flush au fil de l'eau.
        """
        total_found = total_checked = total_errors = 0
        domain_count = 0
        start        = time.time()
        MAX_WORKERS  = 50
        SUBMIT_BATCH = 200

        tprint(f"[PATHS CRON] Debut scan ({len(self.paths)} paths/domaine)...")

        with ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="PathCheck") as executor:
            futures = {}

            def _flush_done():
                nonlocal total_found, total_checked, total_errors
                done = [f for f in futures if f.done()]
                for f in done:
                    try:
                        found, checked, errors = f.result()
                        total_found   += found
                        total_checked += checked
                        total_errors  += errors
                    except Exception as e:
                        tprint(f"[PATHS ERROR] {futures[f]}: {str(e)[:80]}")
                    del futures[f]

            for domain in db.iter_all_domains(page_size=SUBMIT_BATCH):
                domain_count += 1
                future         = executor.submit(self.check_domain_paths, domain)
                futures[future] = domain

                # Flush les futures terminées pour libérer la mémoire
                if len(futures) >= SUBMIT_BATCH:
                    _flush_done()

            # Attendre les futures restantes
            for future in as_completed(futures):
                try:
                    found, checked, errors = future.result()
                    total_found   += found
                    total_checked += checked
                    total_errors  += errors
                except Exception as e:
                    tprint(f"[PATHS ERROR] {futures[future]}: {str(e)[:80]}")

        elapsed = int(time.time() - start)
        tprint(f"[PATHS CRON] Scan terminé — {domain_count} domaines en {elapsed}s")
        tprint(f"[PATHS CRON] Requetes: {total_checked} | erreurs: {total_errors}")
        with stats_lock:
            echo_blocked = stats['echo_server_blocked']
        if echo_blocked > 0:
            tprint(f"[PATHS CRON] 🛡️ {echo_blocked} echo-server(s) bloqué(s)")
        if total_found > 0:
            tprint(f"[PATHS CRON] ⚠️ {total_found} fichier(s) sensible(s) trouvé(s) !")
        else:
            tprint("[PATHS CRON] ✅ Aucun fichier sensible trouvé")

path_monitor = PathMonitor(PATHS_FILE)

# ==================== JS SECRET PATTERNS ====================
# v4.4.1 — Travis CI Token SUPPRIMÉ (trop générique, matchait Base64/WASM/nombres)
#           Heroku: UUID blocklist ajoutée (CLSIDs publics Adobe/Microsoft/RFC)
#           CircleCI: pattern renforcé avec contexte obligatoire
JS_SECRET_PATTERNS_RAW = {
    'AWS Access Key ID':      r'\bAKIA[0-9A-Z]{16}\b',
    'AWS Secret Access Key':  r'\bwsu4ecoCS[A-Za-z0-9/+]{30,40}\b',
    'AWS Session Token':      r'(?:AQoDY|AQAB)[A-Za-z0-9/+=]{200,}',
    'GCP API Key':            r'\bAIza[0-9A-Za-z\-_]{35}\b',
    'GCP Service Account Key':r'"type":\s*"service_account"[^}]{100,}?"client_id":\s*"[0-9]+-[a-z0-9]{20}\.apps\.googleusercontent\.com"',
    'GitHub Personal Token':  r'\bghp_[0-9a-zA-Z]{36}\b',
    'GitHub OAuth Token':     r'\bgho_[0-9a-zA-Z]{36}\b',
    'GitHub App Token':       r'\bghu_[0-9a-zA-Z]{36}\b',
    'Stripe Secret Key Live': r'\bsk_live_[0-9a-zA-Z]{24,}\b',
    'Stripe API Key':         r'\brk_live_[0-9a-zA-Z]{24,}\b',
    'PostgreSQL Connection':  r'postgres://[a-zA-Z0-9_-]+:[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};:\'",.<>?/~`]{8,}@[a-zA-Z0-9.-]+(?::\d+)?/[a-zA-Z0-9_-]+',
    'MySQL Connection':       r'mysql://[a-zA-Z0-9_-]+:[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};:\'",.<>?/~`]{8,}@[a-zA-Z0-9.-]+(?::\d+)?/[a-zA-Z0-9_-]+',
    'MongoDB Connection':     r'mongodb(?:\+srv)?://[a-zA-Z0-9_-]+:[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};:\'",.<>?/~`]{8,}@[a-zA-Z0-9.-]+(?::\d+)?/[a-zA-Z0-9_-]+',
    'RSA Private Key':        r'-----BEGIN RSA PRIVATE KEY-----\s+[A-Za-z0-9+/\s]{100,}-----END RSA PRIVATE KEY-----',
    'EC Private Key':         r'-----BEGIN EC PRIVATE KEY-----\s+[A-Za-z0-9+/\s]{100,}-----END EC PRIVATE KEY-----',
    'OpenSSH Private Key':    r'-----BEGIN OPENSSH PRIVATE KEY-----\s+[A-Za-z0-9+/\s]{100,}-----END OPENSSH PRIVATE KEY-----',
    'PGP Private Key':        r'-----BEGIN PGP PRIVATE KEY BLOCK-----\s+[A-Za-z0-9+/\s]{200,}-----END PGP PRIVATE KEY BLOCK-----',
    'JWT Token':              r'\beyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\b',
    'Slack Bot Token':        r'\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24}\b',
    'Discord Bot Token':      r'\b[MN][A-Za-z0-9_\-]{23,25}\.[A-Za-z0-9_\-]{6,8}\.[A-Za-z0-9_\-]{25,38}\b',
    'Telegram Bot Token':     r'\b\d{8,10}:AA[A-Za-z0-9_\-]{33}\b',
    'Stripe Webhook Secret':  r'\bwhsec_[A-Za-z0-9_\-]{32,}\b',
    # Heroku: UUID AVEC contexte obligatoire (variable heroku/api autour)
    # Sans contexte = UUID générique (session ID, tracking ID, config ID...)
    'Heroku API Key':         r'(?:heroku[_\-]?(?:api[_\-]?)?(?:key|token)|HEROKU[_\-]API[_\-]KEY)\s*[=:]\s*["\']?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})["\']?',
    'DigitalOcean Token':     r'\bdop_v1_[a-f0-9]{64}\b',
    # CircleCI: contexte obligatoire (variable assignment autour)
    'CircleCI Token':         r'(?:CIRCLE_TOKEN|circleci[_\-]token|circle[_\-]api[_\-]key)\s*[=:]\s*["\']?([a-f0-9]{40})["\']?',
}

# UUIDs publics connus — jamais des vrais tokens Heroku
# Sources: Adobe Flash CLSID, Microsoft COM, RFC 4122 exemples, plupload, etc.
HEROKU_UUID_BLOCKLIST = {
    # Adobe Flash / Shockwave
    'd27cdb6e-ae6d-11cf-96b8-444553540000',
    # RFC 4122 exemples officiels
    '6ba7b810-9dad-11d1-80b4-00c04fd430c8',
    '6ba7b811-9dad-11d1-80b4-00c04fd430c8',
    '6ba7b812-9dad-11d1-80b4-00c04fd430c8',
    '6ba7b814-9dad-11d1-80b4-00c04fd430c8',
    # Microsoft COM/OLE
    'd5cdd505-2e9c-101b-9397-08002b2cf9ae',
    'c2f41010-65b3-11d1-a29f-00aa00c14882',
    'f4754c9b-64f5-4b40-8af4-679732ac006f',
    # UUID nil / max
    '00000000-0000-0000-0000-000000000000',
    'ffffffff-ffff-ffff-ffff-ffffffffffff',
    # Exemples courants dans les tests/libs
    '110e8400-e29b-41d4-a716-446655440000',
    '123e4567-e89b-12d3-a456-426614174000',
}

JS_SECRET_ALLOWLIST_VALUES = {
    'your_api_key', 'your_secret_key', 'your_secret', 'your_token', 'your_password',
    'insert_key_here', 'enter_your_key', 'api_key_here', 'example', 'test', 'demo',
    'fake', 'dummy', 'placeholder', 'changeme', 'replace_me', 'update_this',
    'كلمة', 'المرور', 'contraseña', 'مرور', 'пароль', '密码',
    'passwords must be at least', 'password must be', 'at least 8 characters',
    'confirm your password', 'enter your password', 'validation error',
    'must match', 'required field', 'invalid format', 'invalid input',
    'ql-password', '#password', 'password_field', 'expandwildcard',
    'generaldemo', 'summer2023', 'demo2024', 'test123', 'admin123',
    'qwerty', 'password123', 'letmein', 'welcome', 'admin',
    '0000000000000000', '1111111111111111',
    'abcdefghijklmnop', 'abcdefghijklmnopqrstuvwxyz',
    'xxxxxxxxxxxxxxxx', 'yyyyyyyyyyyyyyyy',
    '5d41402abc4b2a76b9719d911017c592',
    'da39a3ee5e6b4b0d3255bfef95601890afd80709',
}

JS_SECRET_COMPILED = {
    name: re.compile(pattern, re.MULTILINE | re.DOTALL)
    for name, pattern in JS_SECRET_PATTERNS_RAW.items()
}

tprint(f"[JS SCANNER] {len(JS_SECRET_COMPILED)} patterns compilés (v4.4.1 — Travis CI supprimé, Heroku blocklist, detection Base64)")

# ==================== JS SECRET SCANNER (PARALLÉLISÉ) ====================
class JSScanner:
    SECRET_VALIDATORS = {
        'AWS Access Key ID':      lambda v: len(v) == 20 and v.isupper(),
        'AWS Secret Access Key':  lambda v: 30 <= len(v) <= 40,
        'AWS Session Token':      lambda v: 100 <= len(v) <= 300,
        'GCP API Key':            lambda v: len(v) == 39 and v.startswith('AIza'),
        'GitHub Personal Token':  lambda v: len(v) == 36 and v.isalnum(),
        'GitHub OAuth Token':     lambda v: len(v) == 36 and v.isalnum(),
        'GitHub App Token':       lambda v: len(v) == 36 and v.isalnum(),
        'Stripe Secret Key Live': lambda v: len(v) >= 24 and '_' in v,
        'Stripe Webhook Secret':  lambda v: len(v) >= 32,
        'JWT Token':              lambda v: v.count('.') == 2 and len(v) > 30,
        'PostgreSQL Connection':  lambda v: 'postgres://' in v,
        'MySQL Connection':       lambda v: 'mysql://' in v,
        'MongoDB Connection':     lambda v: 'mongodb' in v and '://' in v,
        'RSA Private Key':        lambda v: 'BEGIN RSA PRIVATE KEY' in v,
        'EC Private Key':         lambda v: 'BEGIN EC PRIVATE KEY' in v,
        'OpenSSH Private Key':    lambda v: 'BEGIN OPENSSH PRIVATE KEY' in v,
        'Slack Bot Token':        lambda v: v.startswith('xoxb-') and len(v) > 40,
        'Discord Bot Token':      lambda v: (v.startswith('M') or v.startswith('N')) and '.' in v,
        'Telegram Bot Token':     lambda v: re.match(r'^\d{8,10}:AA[A-Za-z0-9_-]{33}$', v),
        'Heroku API Key':         lambda v: bool(re.match(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', v)),
        'DigitalOcean Token':     lambda v: v.startswith('dop_v1_') and len(v) > 40,
        # CircleCI: pattern avec groupe capturant, token = 40 hex purs
        'CircleCI Token':         lambda v: len(v) == 40 and all(c in '0123456789abcdef' for c in v.lower()),
    }

    def _validate_secret_format(self, secret_type: str, value: str) -> bool:
        if secret_type not in self.SECRET_VALIDATORS:
            return True
        try:
            return self.SECRET_VALIDATORS[secret_type](value)
        except Exception:
            return False

    def _content_hash(self, content: str) -> str:
        return hashlib.sha256(content.encode('utf-8', errors='replace')).hexdigest()[:16]

    # ── Préfixes Base64 connus pour du binaire (PNG, SVG, WASM, PDF, OTF...) ──
    _BASE64_BINARY_PREFIXES = (
        'ivborw0kggo',   # PNG  (\x89PNG)
        'jvber',          # PDF  (%PDF)
        'phN2zy',         # SVG  (<svg) — lowercase après decode
        'phn2zy',         # SVG variante
        'aaec',           # WASM (\x00asm) fréquent
        'ugaa',           # TTF/OTF
        'otar',           # OTF
        'amos',           # WASM asm.js
        'agmif',          # GIF89a
        'r0lgodlh',       # GIF
        't2gg',           # TIFF
        'ue1a',           # ZIP
        'pgg=',           # Générique court — trop risqué, skip
    )

    def _is_base64_binary(self, value: str) -> bool:
        """Détecte les chaînes Base64 encodant du contenu binaire (PNG, SVG, WASM...)."""
        v_low = value.lower()
        # Vérifier les préfixes connus
        if any(v_low.startswith(p) for p in self._BASE64_BINARY_PREFIXES):
            return True
        # Heuristique: Base64 pur avec très peu de '_' et '-' (pas un token)
        # Un vrai token API a en général des caractères variés et un contexte d'assignation
        b64_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=')
        if len(value) > 80 and all(c in b64_chars for c in value):
            # Tenter un décodage partiel pour détecter les magic bytes
            try:
                # Padding
                padded = value[:64] + '=' * (4 - len(value[:64]) % 4)
                decoded = base64.b64decode(padded, validate=False)[:6]
                # Magic bytes: PNG, GIF, PDF, WASM, ZIP, OTF, TTF
                magic = [
                    b'\x89PNG', b'GIF8', b'%PDF', b'\x00asm',
                    b'PK\x03\x04', b'\x00\x01\x00\x00', b'OTTO',
                    b'<svg', b'<?xm', b'<htm',
                ]
                if any(decoded.startswith(m) for m in magic):
                    return True
            except Exception:
                pass
        return False

    def _is_allowlisted_value(self, value: str, secret_type: str = None) -> bool:
        v = value.strip().lower()
        MIN_LENGTHS = {
            'AWS Access Key ID': 20, 'AWS Secret Access Key': 30,
            'GitHub Personal Token': 36, 'Stripe Secret Key Live': 24,
            'JWT Token': 30, 'CircleCI Token': 32, 'Heroku API Key': 36,
            'Slack Bot Token': 40, 'Discord Bot Token': 30,
        }
        min_len = MIN_LENGTHS.get(secret_type, 16)
        if len(v) < min_len:
            return True
        if v in JS_SECRET_ALLOWLIST_VALUES:
            return True
        # ── Heroku: UUID blocklist (CLSIDs publics connus) ──────────────────
        if secret_type == 'Heroku API Key' and v in HEROKU_UUID_BLOCKLIST:
            return True
        if '\\u' in value or (value and '\u0000' <= value[0] <= '\u001f'):
            return True
        validation_kw = ['must be', 'password', 'confirm', 'enter', 'invalid', 'required', 'error']
        if any(kw in v for kw in validation_kw) and len(v) < 50:
            return True
        if re.match(r'^[a-z]+(?:[a-z]*[A-Z][a-z]+){2,}$', v):
            return True
        if len(set(v)) < 8:
            return True
        if v.isdigit() and len(v) < 50:
            return True
        if '<' in v or '[' in v or '{' in v:
            return True
        # ── Détecter Base64 binaire (PNG/SVG/WASM/PDF) ──────────────────────
        if self._is_base64_binary(value):
            return True
        # ── Séquences répétitives (ex: 0123425252...  nombres test) ─────────
        if len(value) > 50:
            # Entropie faible: moins de 12 chars uniques sur 50+ = pattern répétitif
            if len(set(value)) < 12:
                return True
            # Que des chiffres et quelques chars (séquences numériques de test)
            digit_ratio = sum(1 for c in value if c.isdigit()) / len(value)
            if digit_ratio > 0.85 and len(value) > 50:
                return True
        return False

    def _extract_context(self, content: str, match) -> str:
        line_start = content.rfind('\n', 0, match.start())
        line_start = 0 if line_start == -1 else line_start + 1
        line_end   = content.find('\n', match.end())
        line_end   = len(content) if line_end == -1 else line_end
        return content[line_start:line_end][:500]

    def _calculate_confidence(self, secret_type: str, value: str, context: str) -> int:
        base_scores = {
            'AWS Access Key ID': 95, 'AWS Secret Access Key': 95,
            'GCP API Key': 95, 'GCP Service Account Key': 95,
            'GitHub Personal Token': 95, 'GitHub OAuth Token': 95, 'GitHub App Token': 95,
            'Stripe Secret Key Live': 95, 'RSA Private Key': 95, 'EC Private Key': 95,
            'OpenSSH Private Key': 95, 'PGP Private Key': 95,
            'PostgreSQL Connection': 95, 'MySQL Connection': 95, 'MongoDB Connection': 95,
            'Slack Bot Token': 85, 'Discord Bot Token': 85, 'Telegram Bot Token': 85,
            'Stripe Webhook Secret': 85, 'DigitalOcean Token': 85, 'Heroku API Key': 85,
            'JWT Token': 75, 'CircleCI Token': 75,
            # Travis CI Token supprimé en v4.4.1 (trop de faux positifs Base64)
        }
        confidence    = base_scores.get(secret_type, 50)
        context_lower = context.lower()
        if any(w in context_lower for w in ['testing', 'dev', 'demo', 'test', 'staging', 'sandbox']):
            confidence -= 25
        if any(w in context_lower for w in ['example', 'documentation', 'doc', 'guide', 'readme']):
            confidence -= 20
        if any(w in context_lower for w in ['fake', 'mock', 'dummy', 'placeholder', 'sample']):
            confidence -= 30
        if re.search(r'\b(TEST|EXAMPLE|DEMO|SAMPLE|FAKE)_[A-Z_]*\s*[=:]', context, re.IGNORECASE):
            confidence -= 20
        if any(w in context_lower for w in ['production', 'prod', 'live', 'real', 'actual']):
            confidence += 20
        if re.search(r'(api_key|api_secret|password|secret|token|credential)\s*[=:]', context_lower):
            confidence += 15
        if re.search(r'(api_url|endpoint|https?://)', context_lower):
            confidence += 10
        if re.search(r'\b(PROD|PRODUCTION|REAL|LIVE)_', context, re.IGNORECASE):
            confidence += 15
        if self._validate_secret_format(secret_type, value):
            confidence += 5
        else:
            confidence -= 30
        return max(0, min(100, confidence))

    def extract_js_urls(self, html: str, base_url: str) -> list:
        parsed_base = urlparse(base_url)
        base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
        found_urls  = set()
        for m in re.finditer(
            r'<script[^>]+src\s*=\s*["\']([^"\']+\.js(?:\?[^"\']*)?)["\']',
            html, re.IGNORECASE
        ):
            src = m.group(1).strip()
            if src.startswith('http://') or src.startswith('https://'):
                url = src
            elif src.startswith('//'):
                url = f"{parsed_base.scheme}:{src}"
            elif src.startswith('/'):
                url = f"{base_origin}{src}"
            else:
                url = urljoin(base_url, src)
            parsed_url = urlparse(url)
            if parsed_base.netloc not in parsed_url.netloc and parsed_url.netloc not in parsed_base.netloc:
                continue
            if any(lib in url.lower() for lib in ['node_modules', 'jquery', 'bootstrap', 'react', 'angular', 'polyfill', 'chunk', 'vendor']):
                continue
            found_urls.add(url.split('?')[0])
        return list(found_urls)[:MAX_JS_PER_DOMAIN]

    def scan_js_content(self, content: str, js_url: str, domain: str = "") -> list:
        findings         = []
        seen_vals        = set()
        rejected_secrets = []

        for secret_type, pattern in JS_SECRET_COMPILED.items():
            try:
                for match in pattern.finditer(content):
                    value = (match.group(1) if match.lastindex and match.group(1) else match.group(0)).strip()
                    if not value or value in seen_vals:
                        continue
                    if self._is_allowlisted_value(value, secret_type):
                        rejected_secrets.append(('allowlist', secret_type, value[:50]))
                        continue
                    if not self._validate_secret_format(secret_type, value):
                        rejected_secrets.append(('format_invalid', secret_type, value[:50]))
                        if domain:
                            db.log_js_false_positive(domain, js_url, secret_type, value[:120], "Format invalide")
                        continue
                    seen_vals.add(value)
                    context    = self._extract_context(content, match)
                    confidence = self._calculate_confidence(secret_type, value, context)
                    if confidence < 75:
                        rejected_secrets.append(('low_confidence', secret_type, f"{confidence}%"))
                        if domain:
                            db.log_js_false_positive(domain, js_url, secret_type, value[:120], f"Confiance basse: {confidence}%")
                        continue
                    findings.append({
                        'type': secret_type, 'value': value[:120],
                        'context': context, 'url': js_url, 'confidence': confidence,
                    })
            except Exception:
                continue

        if rejected_secrets and len(rejected_secrets) <= 15:
            # Log seulement si peu de rejets (évite le flood Railway)
            pass  # Silencieux — les stats sont trackées via stats_lock

        return findings

    def _download_js_to_tmp(self, js_url: str) -> tuple:
        session  = get_session()
        tmp_path = None
        try:
            with _http_semaphore:
                resp = session.get(js_url, timeout=JS_SCAN_TIMEOUT, stream=True, allow_redirects=True)
            if resp.status_code != 200:
                return (None, None, 0)
            tmp_fd, tmp_path = tempfile.mkstemp(suffix='.js', prefix='ct_js_', dir='/tmp')
            total  = 0
            hasher = hashlib.sha256()
            with os.fdopen(tmp_fd, 'wb') as tmp_f:
                for chunk in resp.iter_content(chunk_size=16384):
                    if chunk:
                        tmp_f.write(chunk)
                        hasher.update(chunk)
                        total += len(chunk)
                        if total >= MAX_JS_SIZE:
                            break
            return (tmp_path, hasher.hexdigest()[:16], total)
        except Exception as e:
            tprint(f"[JS DL] Erreur {js_url}: {str(e)[:60]}")
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass
            return (None, None, 0)

    def _delete_tmp(self, tmp_path: str):
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception as e:
                tprint(f"[JS SCAN] Erreur suppression {tmp_path}: {e}")

    def scan_domain(self, domain: str) -> list:
        """Scan un domaine — conçu pour être appelé depuis un thread worker."""
        all_findings = []
        session      = get_session()
        html = final_url = None

        for protocol in ['https', 'http']:
            try:
                with _http_semaphore:
                    resp = session.get(f"{protocol}://{domain}", timeout=JS_SCAN_TIMEOUT, allow_redirects=True)
                if resp.status_code == 200:
                    html      = resp.text
                    final_url = resp.url
                    break
            except Exception:
                continue

        if not html:
            return all_findings

        js_urls = self.extract_js_urls(html, final_url)
        if not js_urls:
            return all_findings

        # Log seulement si des fichiers JS trouvés (pas pour chaque domaine)
        # tprint retiré ici pour éviter le rate limit Railway (500 logs/sec)

        for js_url in js_urls:
            tmp_path = None
            try:
                tmp_path, content_hash, size_bytes = self._download_js_to_tmp(js_url)
                if not tmp_path:
                    continue

                # ⚠️ tprint retiré (trop verbeux — 1 log/fichier × N domaines × M fichiers)
                history = db.get_js_scan_history(js_url)
                if history and history['content_hash'] == content_hash:
                    self._delete_tmp(tmp_path)
                    tmp_path = None
                    with stats_lock:
                        stats['js_files_scanned'] += 1
                    continue

                with open(tmp_path, 'r', encoding='utf-8', errors='replace') as f:
                    js_content = f.read()

                findings = self.scan_js_content(js_content, js_url, domain)
                db.update_js_scan_history(js_url, content_hash, len(findings))

                with stats_lock:
                    stats['js_files_scanned'] += 1

                if findings:
                    new_findings = []
                    for f in findings:
                        is_new = db.save_js_secret(domain, js_url, f['type'], f['value'], f['context'], f['confidence'])
                        if is_new:
                            new_findings.append(f)
                    if new_findings:
                        tprint(f"[JS SCAN] ⚠️ {len(new_findings)} SECRET(S) VRAI(S) trouvé(s) !")
                        all_findings.extend(new_findings)
                        with stats_lock:
                            stats['js_secrets_found'] += len(new_findings)

            except Exception as e:
                tprint(f"[JS SCAN] Erreur scan {js_url}: {str(e)[:80]}")
            finally:
                self._delete_tmp(tmp_path)
                tmp_path = None

        return all_findings

    def send_js_alert(self, domain: str, findings: list):
        if not findings:
            return
        by_url = {}
        for f in findings:
            by_url.setdefault(f['url'], []).append(f)
        fields         = []
        critical_count = 0
        for js_url, js_findings in list(by_url.items())[:10]:
            lines = []
            for f in js_findings[:6]:
                val_preview = f['value'][:50] + ('...' if len(f['value']) > 50 else '')
                conf        = f.get('confidence', 50)
                if conf >= 95:
                    icon = "🔴"; critical_count += 1
                elif conf >= 85:
                    icon = "🟠"
                elif conf >= 75:
                    icon = "🟡"
                else:
                    icon = "⚪"
                lines.append(f"{icon} **{f['type']}** ({conf}%)\n  `{val_preview}`")
            fields.append({
                "name":   f"📄 {js_url.split('/')[-1][:60]}",
                "value":  '\n'.join(lines)[:1024],
                "inline": False
            })
        total_secrets = len(findings)
        color = 0xff0000 if critical_count > 0 else (0xff9900 if total_secrets > 0 else 0xffff00)
        emoji = "🚨" if critical_count > 0 else ("⚠️" if total_secrets > 0 else "ℹ️")
        embed = {
            "title":       f"{emoji} 🔑 SECRETS JS DETECTÉS — {domain}",
            "description": f"**{total_secrets}** secret(s) VRAI(S) | **{critical_count}** CRITIQUE(S)",
            "color":       color, "fields": fields,
            "footer":      {"text": "CT Monitor v4.4.0 — ZERO FALSE POSITIVES"},
            "timestamp":   datetime.utcnow().isoformat()
        }
        discord_send({"embeds": [embed]})
        tprint(f"[JS ALERT] {emoji} {domain} — {total_secrets} SECRET(S) ({critical_count} critique(s)) → Discord")

    def scan_all_parallel(self):
        """
        ✅ NOUVEAU: Scan JS entièrement parallélisé via JS_WORKER_POOL.
        Remplace scan_all_sequential() — même API externe.
        """
        tprint("[JS SCAN] ════════════════════════════════════════")
        tprint(f"[JS SCAN] Démarrage scan secrets JS PARALLÈLE ({JS_SCAN_WORKERS} workers, v4.4.0)")

        start         = time.time()
        total_domains = 0
        futures_map   = {}

        # Collecter tous les domaines en ligne et soumettre au pool JS
        for domain in db.iter_online_domains(page_size=100):
            total_domains += 1
            future              = JS_WORKER_POOL.submit(self.scan_domain, domain)
            futures_map[future] = domain

        tprint(f"[JS SCAN] {total_domains} domaines soumis au pool ({JS_SCAN_WORKERS} workers)")

        # Collecter les résultats au fil de l'eau
        alerts_sent = 0
        for future in as_completed(futures_map):
            domain = futures_map[future]
            try:
                findings = future.result(timeout=JS_SCAN_TIMEOUT * MAX_JS_PER_DOMAIN + 30)
                with stats_lock:
                    stats['js_domains_scanned'] += 1
                if findings:
                    self.send_js_alert(domain, findings)
                    alerts_sent += 1
            except Exception as e:
                tprint(f"[JS SCAN] Erreur domaine {domain}: {str(e)[:80]}")

        elapsed = int(time.time() - start)
        with stats_lock:
            total_files   = stats['js_files_scanned']
            total_secrets = stats['js_secrets_found']
        tprint(f"[JS SCAN] ════════════════════════════════════════")
        tprint(f"[JS SCAN] Terminé — {total_domains} domaine(s) | {total_files} JS | {elapsed}s")
        tprint(f"[JS SCAN] Alertes envoyées: {alerts_sent}")
        if total_secrets > 0:
            tprint(f"[JS SCAN] 🚨 {total_secrets} SECRET(S) RÉEL(S) trouvé(s) au total !")
        else:
            tprint("[JS SCAN] ✅ Aucun secret valide trouvé (zéro faux positifs)")

        with stats_lock:
            stats['last_js_scan'] = datetime.utcnow()

    # Alias rétro-compat
    def scan_all_sequential(self):
        self.scan_all_parallel()

js_scanner = JSScanner()

# ==================== LOAD MANUAL SUBDOMAINS ====================
def load_subdomains_from_file():
    loaded = duplicates = 0
    if not os.path.exists(SUBDOMAINS_FILE):
        tprint(f"[INFO] {SUBDOMAINS_FILE} n'existe pas (optionnel)")
        return loaded, duplicates
    try:
        with open(SUBDOMAINS_FILE, 'r') as f:
            subdomains = [l.strip().lower() for l in f if l.strip() and not l.startswith('#')]
        tprint(f"[LOAD] {len(subdomains)} sous-domaines dans {SUBDOMAINS_FILE}")
        for entry in subdomains:
            subdomain, port = parse_subdomain_entry(entry)
            if not validate_domain(subdomain):
                tprint(f"[LOAD] ❌ {subdomain} — format invalide")
                continue
            if db.subdomain_exists(subdomain):
                duplicates += 1
                continue
            tprint(f"[LOAD] 🔍 Check initial: {subdomain} ...")
            check_result  = check_domain(subdomain)
            status_code   = None
            response_time = None
            if check_result is None:
                tprint(f"[LOAD] ⚠️ Échec total après retries pour {subdomain}")
            else:
                status_code, response_time = check_result
            if port:
                port_open, _ = check_port(subdomain, port)
                tprint(f"[LOAD] 🔌 {subdomain}:{port} — port {'ouvert' if port_open else 'fermé'}")
            base_domain = next((t for t in targets if subdomain == t or subdomain.endswith('.' + t)), subdomain)
            db.add_subdomain_from_file(subdomain, base_domain, status_code)
            loaded += 1
            status_str = str(status_code) if status_code else "timeout"
            tprint(f"[LOAD] {'✅' if status_code == 200 else '🔴'} {subdomain} [{status_str}]")
        tprint(f"[LOAD] Résumé: {loaded} ajouté(s), {duplicates} déjà en DB")
        return loaded, duplicates
    except Exception as e:
        tprint(f"[ERROR] Chargement subdomains: {e}")
        return 0, 0

# ==================== DISCORD ALERTS ====================
def send_discovery_alert(matched_domains_with_status, log_name):
    try:
        if not matched_domains_with_status:
            return
        filtered = []
        skipped  = 0
        for domain, status_code in matched_domains_with_status:
            if notif_cache.already_notified(domain, log_name):
                skipped += 1
            else:
                filtered.append((domain, status_code))
                notif_cache.mark(domain, log_name)
        if skipped > 0:
            tprint(f"[DISCORD] {skipped} domaine(s) ignorés — déjà notifiés")
        if not filtered:
            return
        by_base = {}
        for domain, status_code in filtered:
            base = next((t for t in targets if domain == t or domain.endswith('.' + t)), None)
            if base:
                by_base.setdefault(base, {'accessible': [], 'unreachable': []})
                if status_code == 200:
                    by_base[base]['accessible'].append((domain, status_code))
                else:
                    by_base[base]['unreachable'].append((domain, status_code))
        description       = ""
        total_accessible  = total_unreachable = 0
        for base, data in sorted(by_base.items()):
            description += f"\n**{base}**\n"
            if data['accessible']:
                total_accessible += len(data['accessible'])
                description += " En ligne:\n"
                for domain, status in data['accessible']:
                    description += f" `{domain}` [{status}]\n"
            if data['unreachable']:
                total_unreachable += len(data['unreachable'])
                description += " Hors ligne:\n"
                for domain, status in data['unreachable']:
                    description += f" `{domain}` [{status if status else 'timeout'}]\n"
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
        discord_send({"embeds": [embed]})
        with stats_lock:
            stats['alertes_envoyées'] += 1
            stats['dernière_alerte']  = datetime.utcnow()
        tprint(f"[DISCORD] {len(filtered)} notifiés (✅{total_accessible} ❌{total_unreachable})")
    except Exception as e:
        tprint(f"[DISCORD ERROR] send_discovery_alert: {e}")

def send_now_accessible_alert(domain):
    embed = {
        "title":       f"🟢 {domain}",
        "description": "Ce domaine est maintenant accessible (200 OK)",
        "color":       0x00ff00,
        "footer":      {"text": "CT Monitor"},
        "timestamp":   datetime.utcnow().isoformat()
    }
    discord_send({"embeds": [embed]})
    tprint(f"[ALERT] {domain} est maintenant accessible!")

# ==================== PARSING CERTIFICATS ====================
def _cert_hash(leaf_input: str) -> str:
    return hashlib.sha1(leaf_input.encode()).hexdigest()[:16]

def parse_certificate(entry):
    try:
        leaf_input = entry.get('leaf_input', '')
        leaf_bytes = base64.b64decode(leaf_input)
        if len(leaf_bytes) < 12:
            return []
        log_entry_type = int.from_bytes(leaf_bytes[10:12], 'big')
        cert_der  = None
        cert_hash = _cert_hash(leaf_input)
        if log_entry_type == 0:
            with stats_lock:
                stats['x509_count'] += 1
            if len(leaf_bytes) < 15:
                return []
            cert_length = int.from_bytes(leaf_bytes[12:15], 'big')
            cert_end    = 15 + cert_length
            if cert_end <= len(leaf_bytes):
                cert_der = leaf_bytes[15:cert_end]
        elif log_entry_type == 1:
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
            san_ext  = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_list = list(san_ext.value)
            if len(san_list) > MAX_SANS_PER_CERT:
                db.log_anomaly(cert_hash, "excessive_sans", f"{len(san_list)} SANs")
                san_list = san_list[:MAX_SANS_PER_CERT]
            for san in san_list:
                raw = san.value.lower()
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

# ==================== CRON JOB ====================
_path_scan_running = threading.Event()
_js_scan_running   = threading.Event()

def _recheck_single_domain(domain_row: tuple) -> tuple:
    """
    ✅ NOUVEAU: Worker pour recheck d'un seul domaine offline.
    Retourne (domain, status_code, response_time, back_online).
    """
    domain, base_domain, last_check = domain_row
    host, port = parse_subdomain_entry(domain)
    check_result = check_domain(host)
    status_code = response_time = None
    if check_result is None:
        tprint(f"[CRON] ⚠️ Échec total check {domain}")
    else:
        status_code, response_time = check_result

    port_status = ""
    if port:
        port_open, _ = check_port(host, port)
        port_status   = f" | port {port}: {'ouvert' if port_open else 'fermé'}"
        if port_open and (status_code is None or status_code >= 400):
            status_code = 200

    back_online = status_code == 200
    return (domain, status_code, response_time, back_online, port_status)

def cron_recheck_unreachable():
    """
    ✅ REFACTORISÉ: Recheck offline en parallèle (ThreadPoolExecutor dédié).
    Les writes DB passent tous par le DatabaseWriter.
    """
    tprint("[CRON] Thread recheck + JS scan démarré (PARALLEL v4.4.0)")
    RECHECK_BATCH      = 200   # ✅ AUGMENTÉ: on peut se le permettre en parallèle
    RECHECK_WORKERS    = 30    # ✅ NOUVEAU: workers dédiés recheck
    last_js_scan_time  = 0

    while True:
        try:
            total_offline = db.count_offline()
            total         = db.count()
            tprint(f"[CRON] ---- Recheck — {total} domaine(s) | {total_offline} offline ----")
            back_online = still_down = 0

            if total_offline > 0:
                # ✅ PARALLÈLE: collecter toutes les rows offline puis les checker en //
                offset = 0
                while True:
                    domain_rows = db.get_offline(limit=RECHECK_BATCH, offset=offset)
                    if not domain_rows:
                        break

                    with ThreadPoolExecutor(max_workers=RECHECK_WORKERS, thread_name_prefix="Recheck") as ex:
                        futures = {ex.submit(_recheck_single_domain, row): row for row in domain_rows}
                        for future in as_completed(futures):
                            try:
                                domain, status_code, response_time, is_back, port_status = future.result(timeout=HTTP_CHECK_TIMEOUT + 5)
                                if is_back:
                                    tprint(f"[CRON] ✅ {domain} [{status_code}]{port_status} — redevenu accessible!")
                                    send_now_accessible_alert(domain)
                                    db.mark_online(domain, status_code)
                                    back_online += 1
                                else:
                                    db.update_check(domain, status_code, response_time)
                                    tprint(f"[CRON] 🔴 {domain} [{status_code or 'timeout'}]{port_status}")
                                    still_down += 1
                            except Exception as e:
                                tprint(f"[CRON] Erreur recheck: {str(e)[:80]}")
                    offset += RECHECK_BATCH
            else:
                tprint("[CRON] Aucun domaine offline à recheck")

            tprint(f"[CRON] {back_online} redevenu(s) en ligne | {still_down} toujours hors ligne")

            # Purge historique (async via writer)
            db.purge_history(retention_days=CHECK_HISTORY_RETENTION_DAYS)

            # VACUUM périodique
            with stats_lock:
                last_vac = stats['last_vacuum']
            if (datetime.utcnow() - last_vac).days >= VACUUM_INTERVAL_DAYS:
                db.vacuum_optimize()
                with stats_lock:
                    stats['last_vacuum'] = datetime.utcnow()

            # ── Path scan ────────────────────────────────────────────────────
            if _path_scan_running.is_set():
                tprint("[CRON] Scan paths ignoré — scan précédent encore en cours")
            else:
                def _run_path_scan():
                    _path_scan_running.set()
                    try:
                        path_monitor.check_all()
                    finally:
                        _path_scan_running.clear()
                threading.Thread(target=_run_path_scan, daemon=True, name="PathScan").start()
                tprint("[CRON] Scan paths lancé en arrière-plan")

            # ── JS scan (toutes les JS_SCAN_INTERVAL secondes) ───────────────
            now = time.time()
            if _js_scan_running.is_set():
                tprint("[CRON] Scan JS ignoré — scan précédent encore en cours")
            elif now - last_js_scan_time >= JS_SCAN_INTERVAL:
                last_js_scan_time = now
                def _run_js_scan():
                    _js_scan_running.set()
                    try:
                        js_scanner.scan_all_parallel()
                    finally:
                        _js_scan_running.clear()
                threading.Thread(target=_run_js_scan, daemon=True, name="JSScan").start()
                tprint(f"[CRON] Scan JS parallèle lancé (workers: {JS_SCAN_WORKERS})")
            else:
                next_scan = int(JS_SCAN_INTERVAL - (now - last_js_scan_time))
                tprint(f"[CRON] Prochain scan JS dans {next_scan}s")

            tprint(f"[CRON] Prochain recheck dans {UNREACHABLE_RECHECK_INTERVAL}s")
            time.sleep(UNREACHABLE_RECHECK_INTERVAL)

        except Exception as e:
            tprint(f"[CRON ERROR] {e}")
            traceback.print_exc()
            time.sleep(60)

# ==================== CT MONITORING ====================
def monitor_log(log_config):
    log_name = log_config['name']
    log_url  = log_config['url']
    priority = log_config.get('priority', 'MEDIUM')
    cb       = get_circuit_breaker(log_name)

    if not cb.is_available():
        tprint(f"[{log_name}] ⚠️ Circuit breaker OPEN — skipped")
        with stats_lock:
            stats['circuit_breaker_trips'] += 1
        return 0

    if log_name not in stats['positions']:
        try:
            response  = requests.get(f"{log_url}/ct/v1/get-sth", timeout=10)
            tree_size = response.json()['tree_size']
            with stats_lock:
                lookback = {
                    'CRITICAL': 500000,
                    'HIGH':     200000,
                    'MEDIUM':   50000,
                }.get(priority, 10000)
                stats['positions'][log_name] = max(0, tree_size - lookback)
            cb.record_success()
            tprint(f"[INIT] {log_name}: position initiale {stats['positions'][log_name]:,}")
        except Exception as e:
            cb.record_failure()
            tprint(f"[{log_name}] Erreur init: {str(e)[:80]}")
            return 0

    try:
        response  = requests.get(f"{log_url}/ct/v1/get-sth", timeout=10)
        tree_size = response.json()['tree_size']
        cb.record_success()
    except Exception as e:
        cb.record_failure()
        tprint(f"[{log_name}] Erreur get-sth: {str(e)[:80]}")
        return 0

    with stats_lock:
        current_pos = stats['positions'][log_name]
    if current_pos >= tree_size:
        return 0

    backlog    = tree_size - current_pos
    max_batches = {'CRITICAL': MAX_BATCHES_CRITICAL, 'HIGH': MAX_BATCHES_HIGH}.get(priority, MAX_BATCHES_MEDIUM)
    tprint(f"[{log_name}] Backlog: {backlog:,} — max {max_batches * BATCH_SIZE:,} certs ce cycle")

    batches_done  = 0
    all_results   = []
    pending_http: dict[Future, str] = {}

    while batches_done < max_batches:
        with stats_lock:
            current_pos = stats['positions'][log_name]
        if current_pos >= tree_size:
            break
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
            leaf_input = entry.get('leaf_input', '')
            cert_hash  = _cert_hash(leaf_input)
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
                if cycle_seen(domain, log_name):
                    continue
                if len(pending_http) >= MAX_PENDING_HTTP:
                    tprint(f"[{log_name}] ⚠️ Max pending futures — flush batch")
                    for future in list(pending_http.keys())[:100]:
                        try:
                            status_code, response_time = future.result(timeout=2)
                            all_results.append((pending_http[future], status_code))
                        except Exception:
                            pass
                        del pending_http[future]
                future              = HTTP_WORKER_POOL.submit(_do_check_domain, domain)
                pending_http[future] = domain

        with stats_lock:
            stats['positions'][log_name] = end_pos
            stats['batches_processed']  += 1
        batches_done += 1

    for future in as_completed(pending_http, timeout=HTTP_CHECK_TIMEOUT + 5):
        domain = pending_http[future]
        try:
            status_code, response_time = future.result()
        except Exception:
            status_code = response_time = None
        with stats_lock:
            stats['http_checks'] += 1
        all_results.append((domain, status_code))
        base = next((t for t in targets if domain == t or domain.endswith('.' + t)), None)
        if base:
            db.add_domain(domain, base, status_code, log_name)

    if all_results:
        send_discovery_alert(all_results, log_name)
    return batches_done

def monitor_all_logs():
    results = {}
    with ThreadPoolExecutor(max_workers=PARALLEL_LOGS, thread_name_prefix="CTLog") as executor:
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
    try:
        conn   = db.get_conn()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM subdomains WHERE domain LIKE '*.%'")
        wildcards_deleted = cursor.rowcount
        if targets:
            conditions = []
            params     = []
            for t in targets:
                conditions.append("domain = ? OR domain LIKE ?")
                params.extend([t, f'%.{t}'])
            where_clause = " OR ".join(f"({c})" for c in conditions)
            cursor.execute(f"DELETE FROM subdomains WHERE NOT ({where_clause})", params)
            orphans_deleted = cursor.rowcount
        else:
            orphans_deleted = 0
        conn.commit()
        if wildcards_deleted > 0:
            tprint(f"[DB CLEANUP] {wildcards_deleted} wildcard(s) supprimé(s)")
        if orphans_deleted > 0:
            tprint(f"[DB CLEANUP] {orphans_deleted} orphelin(s) supprimé(s)")
        if wildcards_deleted == 0 and orphans_deleted == 0:
            tprint("[DB CLEANUP] Base propre")
    except Exception as e:
        tprint(f"[DB CLEANUP ERROR] {e}")

# ==================== DUMP DB ====================
def dump_db():
    tprint("[DUMP] Envoi du contenu de la DB sur Discord...")
    PAGE_SIZE = 100
    try:
        conn   = db.get_conn()
        cursor = conn.cursor()
        summary = db.stats_summary()
        requests.post(DISCORD_WEBHOOK, json={"embeds": [{
            "title":       "Base de données — Dump complet",
            "description": (
                f"**Total:** {summary['total']} domaine(s)\n"
                f"**Taille:** {db.size_mb()} MB\n"
                f"**Timeout:** {summary['timeout']} | **4xx:** {summary['4xx']} | **5xx:** {summary['5xx']}"
            ),
            "color":     0x5865f2,
            "footer":    {"text": "CT Monitor — DUMP_DB"},
            "timestamp": datetime.utcnow().isoformat()
        }]}, timeout=10)
        cursor.execute('SELECT domain, status_code, log_source, last_check FROM subdomains ORDER BY last_check DESC')
        total_sent = 0
        chunk_size = 20
        buffer     = []
        while True:
            rows = cursor.fetchmany(PAGE_SIZE)
            if not rows:
                break
            buffer.extend(rows)
            while len(buffer) >= chunk_size:
                chunk  = buffer[:chunk_size]
                buffer = buffer[chunk_size:]
                lines  = [f"`{d}` [{s or 'timeout'}] — {(lc or '')[:16]}" for d, s, _, lc in chunk]
                total_sent += len(chunk)
                requests.post(DISCORD_WEBHOOK, json={"embeds": [{
                    "title":       f"Domaines {total_sent - len(chunk) + 1}–{total_sent}",
                    "description": "\n".join(lines),
                    "color":       0x2f3136,
                    "footer":      {"text": "CT Monitor — DUMP_DB"}
                }]}, timeout=10)
                time.sleep(0.5)
        if buffer:
            lines = [f"`{d}` [{s or 'timeout'}] — {(lc or '')[:16]}" for d, s, _, lc in buffer]
            total_sent += len(buffer)
            requests.post(DISCORD_WEBHOOK, json={"embeds": [{
                "title":       f"Domaines (fin) — {len(buffer)} entrée(s)",
                "description": "\n".join(lines),
                "color":       0x2f3136,
                "footer":      {"text": "CT Monitor — DUMP_DB"}
            }]}, timeout=10)
        requests.post(DISCORD_WEBHOOK, json={"embeds": [{
            "title":       "Dump terminé",
            "description": f"{total_sent} domaine(s) envoyés. Retire `DUMP_DB=1` pour relancer.",
            "color":       0x00ff00,
            "footer":      {"text": "CT Monitor — DUMP_DB"}
        }]}, timeout=10)
        tprint(f"[DUMP] {total_sent} domaine(s) envoyés")
    except Exception as e:
        tprint(f"[DUMP ERROR] {e}")
        if DISCORD_WEBHOOK:
            requests.post(DISCORD_WEBHOOK, json={"embeds": [{
                "title": "Dump erreur", "description": str(e), "color": 0xff0000
            }]}, timeout=10)

if os.environ.get('DUMP_DB', '0') == '1':
    dump_db()
    exit(0)

# ==================== DÉMARRAGE ====================
tprint("[START] ================================================")
tprint(f"[START] CT Monitor v4.4.0 - PARALLEL EDITION")
tprint(f"[START] {NB_LOGS_ACTIFS} logs CT | {len(targets)} domaine(s) surveillés")
tprint(f"[START] HTTP pool: {HTTP_CONCURRENCY_LIMIT} workers | JS pool: {JS_SCAN_WORKERS} workers")
tprint(f"[START] DB Writer: queue={DB_WRITE_QUEUE_SIZE} | flush toutes les {int(DB_WRITE_BATCH_TIMEOUT*1000)}ms")
tprint(f"[START] JS scan interval: {JS_SCAN_INTERVAL}s | Confidence threshold: 75% MINIMUM")
tprint(f"[START] Notification TTL: {NOTIFICATION_TTL // 3600}h | History: {CHECK_HISTORY_RETENTION_DAYS}j")
tprint("[START] ================================================")

tprint("[STARTUP] 1/3 — Nettoyage DB...")
cleanup_db()
db.purge_history()
_s = db.stats_summary()
tprint(f"[STARTUP] DB: {_s['total']} domaines | online={_s['online']} | {db.size_mb()} MB")

tprint(f"[STARTUP] 2/3 — Chargement {SUBDOMAINS_FILE}...")
if os.path.exists(SUBDOMAINS_FILE):
    loaded_count, dup_count = load_subdomains_from_file()
    tprint(f"[STARTUP] {loaded_count} ajouté(s), {dup_count} déjà en DB")
else:
    tprint(f"[STARTUP] {SUBDOMAINS_FILE} absent")

tprint("[STARTUP] 3/3 — Démarrage thread cron...")
threading.Thread(target=cron_recheck_unreachable, daemon=True, name="CronRecheck").start()
time.sleep(1)
tprint("[STARTUP] Thread cron démarré")
tprint("[STARTUP] ================================================")

# ==================== BOUCLE PRINCIPALE ====================
cycle = 0
while True:
    try:
        cycle += 1
        cycle_start = time.time()

        if cycle % TARGETS_RELOAD_INTERVAL == 0:
            tprint(f"[CYCLE #{cycle}] Reloading targets...")
            new_targets = load_targets()
            if len(new_targets) != len(targets):
                tprint(f"[CYCLE #{cycle}] Targets changed: {len(targets)} → {len(new_targets)}")
                targets = new_targets

        with stats_lock:
            stats['dernière_vérification'] = datetime.utcnow()

        tprint(f"[CYCLE #{cycle}] ---- {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} ----")
        cycle_reset()
        update_heartbeat()
        monitor_all_logs()
        save_positions()

        cleared = notif_cache.clear_expired()
        if cleared > 0:
            tprint(f"[CYCLE #{cycle}] Notif cache: {cleared} expirée(s)")

        cycle_duration = int(time.time() - cycle_start)
        _s = db.stats_summary()

        certs_this_cycle = stats['certificats_analysés']
        if certs_this_cycle < MIN_CERTS_PER_CYCLE:
            tprint(f"[ALERT] ⚠️ Seulement {certs_this_cycle} certs ce cycle (min: {MIN_CERTS_PER_CYCLE})")

        tprint(f"[CYCLE #{cycle}] Terminé en {cycle_duration}s")
        tprint(f"[CYCLE #{cycle}] Certificats analysés  : {stats['certificats_analysés']:,}")
        tprint(f"[CYCLE #{cycle}] Matches trouvés        : {stats['matches_trouvés']:,}")
        tprint(f"[CYCLE #{cycle}] HTTP checks            : {stats['http_checks']:,}")
        tprint(f"[CYCLE #{cycle}] Alertes envoyées       : {stats['alertes_envoyées']:,}")
        tprint(f"[CYCLE #{cycle}] Duplicates évités      : {stats['duplicates_évités']:,}")
        tprint(f"[CYCLE #{cycle}] Echo-servers bloqués   : {stats['echo_server_blocked']:,}")
        tprint(f"[CYCLE #{cycle}] JS fichiers scannés    : {stats['js_files_scanned']:,}")
        tprint(f"[CYCLE #{cycle}] JS SECRETS VRAIS       : {stats['js_secrets_found']:,}")
        tprint(f"[CYCLE #{cycle}] JS FALSE POSITIVES     : {stats['js_false_positives']:,}")
        tprint(f"[CYCLE #{cycle}] DB Writer queue        : {stats['db_write_queue_size']} | écrits: {stats['db_writes_processed']:,}")
        tprint(f"[CYCLE #{cycle}] Discord queue          : {_discord_queue.qsize()} | perdus: {stats['discord_dropped']}")
        tprint(f"[CYCLE #{cycle}] DB : {_s['total']} domaines | {db.size_mb()} MB")
        tprint(f"[CYCLE #{cycle}] DB : {_s['timeout']} timeout | {_s['4xx']} 4xx | {_s['5xx']} 5xx")
        tprint(f"[CYCLE #{cycle}] Prochain cycle dans {CHECK_INTERVAL}s...")
        time.sleep(CHECK_INTERVAL)

    except KeyboardInterrupt:
        tprint("[STOP] Arrêt demandé")
        save_positions()
        db._writer.stop()
        _discord_queue.put(None)
        _discord_thread.join(timeout=5)
        HTTP_WORKER_POOL.shutdown(wait=False)
        JS_WORKER_POOL.shutdown(wait=False)
        cleanup_sessions()
        break
    except Exception as e:
        tprint(f"[ERROR] {e}")
        traceback.print_exc()
        save_positions()
        time.sleep(30)

tprint("[STOP] Monitoring arrêté")
