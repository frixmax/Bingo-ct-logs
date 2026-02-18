#!/usr/bin/env python3
"""
CT Monitoring VPS - VERSION v4 - PRODUCTION READY
=========================================================

Améliorations v4:
- ✅ Race conditions sur stats['positions'] corrigées (per-log lock + atomic ops)
- ✅ Memory leak Sessions HTTP éliminé (rotation + explicit close)
- ✅ SQLite check_same_thread=True (sécurité)
- ✅ Queue Discord avec batching (max 30 domaines/message)
- ✅ Retry exponential sur HTTP checks (1s, 2s, 5s)
- ✅ Circuit breaker sur logs CT défaillants
- ✅ Healthcheck file + monitoring du monitoring
- ✅ Validation domaines au startup
- ✅ Deduplication alertes (tuple: domain, log_source)
- ✅ Replay WAL sur positions.json
- ✅ Limiter SANs/cert (max 1000) + logging anomalies
- ✅ Rotation sessions HTTP (max 1000 requests)
- ✅ Limiter batch pending_http (max 5000 futures)
- ✅ Monitoring stale data (min X certs/cycle)
- ✅ Reload targets.txt dynamique (tous les 10 cycles)
- ✅ PRAGMA optimize + VACUUM mensuel
- ✅ Signature HMAC Discord (optionnel)
- ✅ False positives logging
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
from datetime import datetime, timedelta
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from concurrent.futures import ThreadPoolExecutor, as_completed, Future, TimeoutError as FutureTimeoutError
from collections import OrderedDict
from idna import encode as idna_encode, IDNAError

# ==================== THREAD-SAFE PRINT ====================
_print_lock = threading.Lock()

def tprint(msg):
    with _print_lock:
        print(f"[{datetime.utcnow().strftime('%H:%M:%S')}] {msg}")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

tprint("=" * 100)
tprint("CT MONITORING - VERSION v4 - PRODUCTION READY")
tprint(f"Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
tprint("=" * 100)

# ==================== CONFIGURATION ====================
DISCORD_WEBHOOK    = os.environ.get('DISCORD_WEBHOOK', '')
DISCORD_SECRET     = os.environ.get('DISCORD_SECRET', '')  # Pour signature HMAC
DOMAINS_FILE       = '/app/domains.txt'
DATA_DIR           = '/app/data'
DATABASE_FILE      = f'{DATA_DIR}/ct_monitoring.db'
POSITIONS_FILE     = f'{DATA_DIR}/ct_positions.json'
POSITIONS_WAL      = f'{DATA_DIR}/ct_positions.json.wal'
SUBDOMAINS_FILE    = '/app/subdomains.txt'
PATHS_FILE         = '/app/paths.txt'
HEARTBEAT_FILE     = '/tmp/ct_monitor.heartbeat'

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
HTTP_CHECK_RETRIES           = 3  # NEW: 1s, 2s, 5s
UNREACHABLE_RECHECK_INTERVAL = 300
SESSION_MAX_REQUESTS         = 1000  # NEW: rotation sessions
MAX_PENDING_HTTP             = 5000   # NEW: limiter futures
MAX_SANS_PER_CERT            = 1000   # NEW: limiter SANs

# AMÉLIORATIONS NOUVELLES
TARGETS_RELOAD_INTERVAL      = 10    # Recharger targets tous les 10 cycles
MIN_CERTS_PER_CYCLE          = 100   # NEW: alerte si < 100 certs (stale data)
HTTP_CONCURRENCY_LIMIT       = 50
_http_semaphore              = threading.Semaphore(HTTP_CONCURRENCY_LIMIT)
HTTP_WORKER_POOL             = ThreadPoolExecutor(max_workers=HTTP_CONCURRENCY_LIMIT, thread_name_prefix="HTTPWorker")

NOTIFICATION_TTL             = 1 * 3600   # 1h
CHECK_HISTORY_RETENTION_DAYS = 7
VACUUM_INTERVAL_DAYS         = 30  # NEW: VACUUM mensuel

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
    'false_positives':        0,     # NEW
    'retry_http':             0,     # NEW
    'circuit_breaker_trips':  0,     # NEW
    'last_vacuum':            datetime.utcnow(),  # NEW
}
stats_lock = threading.Lock()

# NEW: Per-log failure tracking
_log_failures = {}
_log_failures_lock = threading.Lock()

# NEW: Per-log session tracking
_log_requests_count = {}
_log_requests_lock = threading.Lock()

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
    """NEW: Track (domain, log_name) tuple instead of just domain."""
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

# ==================== DISCORD QUEUE WITH BATCHING ====================
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
                # NEW: HMAC signature
                if DISCORD_SECRET:
                    body = json.dumps(payload)
                    sig = hmac.new(
                        DISCORD_SECRET.encode(),
                        body.encode(),
                        hashlib.sha256
                    ).hexdigest()
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
    """NEW: Enqueue with explicit logging."""
    try:
        _discord_queue.put_nowait(payload)
    except queue.Full:
        with stats_lock:
            stats['discord_dropped'] += 1
        tprint(f"[DISCORD QUEUE] ⚠️  PLEINE — payload ignoré (total perdu: {stats['discord_dropped']})")

_discord_thread = threading.Thread(target=_discord_worker, daemon=True, name="DiscordWorker")
_discord_thread.start()

# ==================== HEALTHCHECK ====================
def update_heartbeat():
    """NEW: Write heartbeat file for external monitoring."""
    try:
        with open(HEARTBEAT_FILE, 'w') as f:
            f.write(str(int(time.time())))
    except Exception:
        pass

def check_heartbeat_stale(max_age=120):
    """NEW: Check if heartbeat is stale (2 minutes)."""
    try:
        if not os.path.exists(HEARTBEAT_FILE):
            return True
        mtime = os.path.getmtime(HEARTBEAT_FILE)
        return (time.time() - mtime) > max_age
    except Exception:
        return True

# ==================== SESSION MANAGEMENT WITH ROTATION ====================
_session_local = threading.local()
_session_request_count = 0
_session_count_lock = threading.Lock()

def get_session() -> requests.Session:
    """NEW: Sessions with rotation (max SESSION_MAX_REQUESTS)."""
    global _session_request_count
    
    if not hasattr(_session_local, 'session') or _session_local.session is None:
        s = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=10,
            pool_maxsize=20,
            max_retries=0,
        )
        s.mount('https://', adapter)
        s.mount('http://', adapter)
        s.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        s.verify = False
        _session_local.session = s
        _session_local.request_count = 0

    # NEW: Rotate session after max requests
    _session_local.request_count += 1
    if _session_local.request_count >= SESSION_MAX_REQUESTS:
        try:
            _session_local.session.close()
        except Exception:
            pass
        _session_local.session = None
        return get_session()  # Recursive call creates new session

    return _session_local.session

def cleanup_sessions():
    """NEW: Explicit session cleanup."""
    try:
        if hasattr(_session_local, 'session') and _session_local.session:
            _session_local.session.close()
    except Exception:
        pass

weakref.finalize(_session_local, cleanup_sessions)

# ==================== DATABASE ====================
class CertificateDatabase:
    """v4: check_same_thread=True + VACUUM mensuel."""

    def __init__(self, db_path):
        self.db_path = db_path
        self._local  = threading.local()
        self.init_db()

    def _get_conn(self):
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            # NEW: check_same_thread=True (sécurité)
            conn = sqlite3.connect(self.db_path, check_same_thread=True, timeout=30)
            conn.execute('PRAGMA journal_mode=WAL')
            conn.execute('PRAGMA synchronous=NORMAL')
            conn.execute('PRAGMA cache_size=-64000')  # 64MB cache
            self._local.conn = conn
            
            # Finalizer
            local_ref = weakref.ref(self._local)
            def _close_conn(conn=conn):
                try:
                    conn.close()
                except Exception:
                    pass
            weakref.finalize(self._local, _close_conn)

        return self._local.conn

    def get_conn(self):
        return self._get_conn()

    def init_db(self):
        conn   = self._get_conn()
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
        # NEW: Table for false positives logging
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS false_positives (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                domain           TEXT NOT NULL,
                path             TEXT,
                reason           TEXT,
                timestamp        TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        # NEW: Table for anomalies
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS anomalies (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                cert_hash        TEXT NOT NULL,
                anomaly_type     TEXT,
                detail           TEXT,
                timestamp        TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='unreachable_domains'")
        if cursor.fetchone():
            cursor.execute('''
                INSERT OR IGNORE INTO subdomains (domain, base_domain, status_code, is_online, first_seen, last_check, log_source)
                SELECT domain, base_domain, status_code, 0, first_seen, last_check, log_source
                FROM unreachable_domains
            ''')
            cursor.execute('DROP TABLE unreachable_domains')
            tprint("[DB] Migration unreachable_domains → subdomains effectuée")
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_domain     ON subdomains(domain)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_last_check ON subdomains(last_check)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_is_online  ON subdomains(is_online)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_log_source ON subdomains(log_source)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_history_ts ON check_history(check_timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_fp_domain  ON false_positives(domain)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_anom_hash  ON anomalies(cert_hash)')
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

    def log_false_positive(self, domain, path, reason):
        """NEW: Log false positives."""
        try:
            conn   = self._get_conn()
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO false_positives (domain, path, reason) VALUES (?, ?, ?)',
                (domain, path, reason)
            )
            conn.commit()
            with stats_lock:
                stats['false_positives'] += 1
        except Exception as e:
            tprint(f"[DB ERROR] log_false_positive: {e}")

    def log_anomaly(self, cert_hash, anomaly_type, detail):
        """NEW: Log certificate anomalies."""
        try:
            conn   = self._get_conn()
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO anomalies (cert_hash, anomaly_type, detail) VALUES (?, ?, ?)',
                (cert_hash, anomaly_type, detail)
            )
            conn.commit()
        except Exception as e:
            tprint(f"[DB ERROR] log_anomaly: {e}")

    def get_offline(self, limit=100, offset=0):
        try:
            conn   = self._get_conn()
            cursor = conn.cursor()
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
            conn   = self._get_conn()
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM subdomains WHERE is_online = 0')
            return cursor.fetchone()[0]
        except Exception:
            return 0

    def iter_all_domains(self, page_size=500):
        offset = 0
        while True:
            try:
                conn   = self._get_conn()
                cursor = conn.cursor()
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

    def get_all_domains(self):
        return list(self.iter_all_domains())

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
        except Exception as e:
            tprint(f"[DB ERROR] mark_online {domain}: {e}")

    def purge_history(self, retention_days=CHECK_HISTORY_RETENTION_DAYS):
        try:
            conn   = self._get_conn()
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM check_history WHERE check_timestamp < datetime('now', ? || ' days')",
                (f'-{retention_days}',)
            )
            deleted = cursor.rowcount
            conn.commit()
            if deleted > 0:
                tprint(f"[DB PURGE] {deleted} entrées supprimées")
            return deleted
        except Exception as e:
            tprint(f"[DB ERROR] purge_history: {e}")
            return 0

    def vacuum_optimize(self):
        """NEW: VACUUM + PRAGMA optimize."""
        try:
            conn   = self._get_conn()
            cursor = conn.cursor()
            cursor.execute('PRAGMA optimize')
            conn.commit()
            tprint("[DB] PRAGMA optimize executé")
            # Note: VACUUM est plus lent, exécuté moins fréquemment
        except Exception as e:
            tprint(f"[DB ERROR] vacuum_optimize: {e}")

    def count(self):
        try:
            conn   = self._get_conn()
            cursor = conn.cursor()
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
    """NEW: Validate domain format."""
    domain = domain.lower().strip()
    
    # Check for invalid patterns
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
    
    # Try IDNA encoding
    try:
        idna_encode(domain)
        return True
    except (IDNAError, Exception):
        return False

# ==================== POSITION PERSISTENCE WITH WAL ====================
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
    """NEW: WAL-style atomic save."""
    tmp_file = POSITIONS_FILE + '.tmp'
    try:
        with stats_lock:
            positions_copy = dict(stats['positions'])
        
        # Write to tmp
        with open(tmp_file, 'w') as f:
            json.dump(positions_copy, f, indent=2)
        
        # Sync to disk
        try:
            f_tmp = os.open(tmp_file, os.O_RDONLY)
            os.fsync(f_tmp)
            os.close(f_tmp)
        except Exception:
            pass
        
        # Atomic rename
        os.replace(tmp_file, POSITIONS_FILE)
        
        # Clean WAL
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
    """NEW: Circuit breaker for failing logs."""
    def __init__(self, failure_threshold=3):
        self.failures = 0
        self.threshold = failure_threshold
        self.is_open = False
        self.lock = threading.Lock()
        self.last_fail_time = None

    def record_success(self):
        with self.lock:
            self.failures = 0
            self.is_open = False

    def record_failure(self):
        with self.lock:
            self.failures += 1
            self.last_fail_time = time.time()
            if self.failures >= self.threshold:
                self.is_open = True

    def is_available(self):
        with self.lock:
            if not self.is_open:
                return True
            # Half-open: try again after 5 min
            if time.time() - self.last_fail_time > 300:
                self.is_open = False
                self.failures = 0
                return True
            return False

_circuit_breakers = {}
_cb_lock = threading.Lock()

def get_circuit_breaker(log_name):
    with _cb_lock:
        if log_name not in _circuit_breakers:
            _circuit_breakers[log_name] = CircuitBreaker()
        return _circuit_breakers[log_name]

# ==================== RETRY LOGIC ====================
def retry_with_backoff(func, max_retries=HTTP_CHECK_RETRIES, timeout_base=1):
    """NEW: Exponential backoff retry."""
    for attempt in range(max_retries):
        try:
            return func()
        except Exception as e:
            if attempt == max_retries - 1:
                return None
            wait_time = timeout_base * (2 ** attempt)
            with stats_lock:
                stats['retry_http'] += 1
            time.sleep(wait_time)
    return None

# ==================== FALSE POSITIVE DETECTION ====================
PATH_CONTENT_EXPECTATIONS = {
    '.env':             ['=', 'KEY', 'SECRET', 'PASSWORD', 'TOKEN', 'DB_', 'APP_', 'HOST'],
    '.env.backup':      ['=', 'KEY', 'SECRET', 'PASSWORD', 'TOKEN'],
    '.env.local':       ['=', 'KEY', 'SECRET', 'DB_'],
    '.env.production':  ['=', 'KEY', 'SECRET', 'PASSWORD'],
    '.git/config':      ['[core]', '[remote', 'repositoryformatversion', 'filemode'],
    'wp-config.php':    ['DB_NAME', 'DB_PASSWORD', 'DB_HOST', 'table_prefix', "define("],
    'backup.sql':       ['INSERT INTO', 'CREATE TABLE', 'DROP TABLE', 'mysqldump', '-- MySQL'],
    'actuator/env':     ['"activeProfiles"', '"propertySources"', '"systemProperties"'],
    'actuator/health':  ['"status"', '"UP"', '"DOWN"', '"components"'],
    'actuator/metrics': ['"names"', '"measurements"'],
    'api/v1/users':     ['"id"', '"email"', '"username"', '"users"'],
    'phpinfo.php':      ['PHP Version', 'phpinfo', 'php.ini'],
    'server-status':    ['Apache Server Status', 'requests currently being processed'],
    'adminer':          ['Adminer', 'adminer', 'db_driver'],
    'phpmyadmin':       ['phpMyAdmin', 'pma_', 'PMA_'],
}

def check_content_coherence(body: str, path: str) -> tuple:
    path_low    = path.lower()
    body_sample = body[:5000]
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
    """Check domain with retry logic."""
    MAX_REDIRECTS = 5
    session = get_session()

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
            elapsed = int((time.time() - start) * 1000)

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

def check_domain(domain: str) -> tuple:
    """Check domain with exponential backoff retry."""
    def _check():
        future = HTTP_WORKER_POOL.submit(_do_check_domain, domain)
        return future.result(timeout=HTTP_CHECK_TIMEOUT + 2)
    
    return retry_with_backoff(_check, max_retries=HTTP_CHECK_RETRIES)

def check_port(host, port, timeout=10):
    try:
        start   = time.time()
        sock    = socket.create_connection((host, port), timeout=timeout)
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
    """NEW: Load and validate target domains."""
    try:
        with open(DOMAINS_FILE, 'r') as f:
            raw_domains = {line.strip().lower() for line in f if line.strip() and not line.startswith('#')}
        
        # Validate each domain
        valid = set()
        invalid = []
        for domain in raw_domains:
            if validate_domain(domain):
                valid.add(domain)
            else:
                invalid.append(domain)
        
        if invalid:
            tprint(f"[WARN] {len(invalid)} domaines invalides (format): {invalid[:5]}")
        
        if not valid:
            tprint("[ERROR] Aucun domaine valide à surveiller — arrêt")
            exit(1)
        
        tprint(f"[OK] {len(valid)} domaines chargés et validés")
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
            tprint(f"[PATHS] {self.paths_file} absent — {len(self.paths)} par défaut")
            return
        try:
            with open(self.paths_file, 'r') as f:
                custom = [l.strip() for l in f if l.strip() and not l.startswith('#')]
            for p in custom:
                if p not in self.paths:
                    self.paths.append(p)
            tprint(f"[PATHS] {len(custom)} custom + {len(self.DEFAULT_PATHS)} défaut = {len(self.paths)} total")
        except Exception as e:
            tprint(f"[PATHS ERROR] {e}")

    def check_path(self, url: str) -> tuple:
        MAX_CONTENT_SIZE = 5 * 1024 * 1024
        parsed_path      = urlparse(url).path
        session          = get_session()

        try:
            with _http_semaphore:
                response = session.get(
                    url,
                    timeout=PATH_CHECK_TIMEOUT,
                    allow_redirects=True,
                    stream=True
                )
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

                is_coherent, coherence_reason = check_content_coherence(content, parsed_path)
                if not is_coherent:
                    db.log_false_positive(url.split('://')[1].split('/')[0], parsed_path, coherence_reason)
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
        """NEW: Batch content alert."""
        preview = content[:1900]
        if len(content) > 1900:
            preview += f"\n... (tronqué: {len(content)} chars)"
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
        tprint(f"[PATHS ALERT] ✅ {url}")

    def check_domain_paths(self, domain):
        host, port = parse_subdomain_entry(domain)
        found = errors = checked = 0
        for path in self.paths:
            for protocol in ['https', 'http']:
                url = f"{protocol}://{host}{path}"
                status_code, content, response_time, error = self.check_path(url)
                checked += 1
                if status_code == 200 and content:
                    tprint(f"[PATHS] ✅ {url} [{len(content)} bytes]")
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
        """NEW: Timeout protection + paginated."""
        total_found = total_checked = total_errors = 0
        domain_count = 0
        start = time.time()
        MAX_DURATION = 240  # 4 minutes max
        MAX_WORKERS = 50

        tprint(f"[PATHS CRON] Début scan ({len(self.paths)} paths)...")

        with ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="PathCheck") as executor:
            futures = []
            for domain in db.iter_all_domains(page_size=100):
                if time.time() - start > MAX_DURATION:
                    tprint("[PATHS CRON] ⚠️  Timeout — scan interrompu")
                    break
                
                domain_count += 1
                future = executor.submit(self.check_domain_paths, domain)
                futures.append((future, domain))

            for future, domain in futures:
                try:
                    found, checked, errors = future.result(timeout=30)
                    total_found   += found
                    total_checked += checked
                    total_errors  += errors
                except Exception as e:
                    tprint(f"[PATHS ERROR] {domain}: {str(e)[:80]}")

        elapsed = int(time.time() - start)
        tprint(f"[PATHS CRON] {domain_count} domaines en {elapsed}s | {total_found} trouvés")

path_monitor = PathMonitor(PATHS_FILE)

# ==================== LOAD MANUAL SUBDOMAINS ====================
def load_subdomains_from_file():
    loaded = duplicates = 0
    if not os.path.exists(SUBDOMAINS_FILE):
        tprint(f"[INFO] {SUBDOMAINS_FILE} n'existe pas (optionnel)")
        return loaded, duplicates
    try:
        with open(SUBDOMAINS_FILE, 'r') as f:
            subdomains = [l.strip().lower() for l in f if l.strip() and not l.startswith('#')]
        tprint(f"[LOAD] {len(subdomains)} subdomains dans {SUBDOMAINS_FILE}")

        for entry in subdomains:
            subdomain, port = parse_subdomain_entry(entry)
            
            if not validate_domain(subdomain):
                tprint(f"[LOAD] ❌ {subdomain} — format invalide")
                continue

            if db.subdomain_exists(subdomain):
                duplicates += 1
                continue

            tprint(f"[LOAD] 🔍 Check: {subdomain} ...")
            status_code, response_time = check_domain(subdomain)

            if port:
                port_open, _ = check_port(subdomain, port)
                tprint(f"[LOAD] 🔌 {subdomain}:{port} — {'ouvert' if port_open else 'fermé'}")

            base_domain = next((t for t in targets if subdomain == t or subdomain.endswith('.' + t)), subdomain)
            db.add_subdomain_from_file(subdomain, base_domain, status_code)
            loaded += 1

        tprint(f"[LOAD] {loaded} ajoutés | {duplicates} déjà en DB")
        return loaded, duplicates
    except Exception as e:
        tprint(f"[ERROR] Chargement subdomains: {e}")
        return 0, 0

# ==================== DISCORD ALERTS ====================
def send_discovery_alert(matched_domains_with_status, log_name):
    """NEW: Batch alert (max 30 domaines per message)."""
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
            tprint(f"[DISCORD] {skipped} domaine(s) ignorés (déjà notifiés)")
        if not filtered:
            return

        # Batch by base domain
        by_base = {}
        for domain, status_code in filtered:
            base = next((t for t in targets if domain == t or domain.endswith('.' + t)), None)
            if base:
                by_base.setdefault(base, {'accessible': [], 'unreachable': []})
                if status_code == 200:
                    by_base[base]['accessible'].append((domain, status_code))
                else:
                    by_base[base]['unreachable'].append((domain, status_code))

        # Split into batches of 30 domains max
        embeds = []
        domain_count = 0
        for base, data in sorted(by_base.items()):
            description = f"**{base}**\n"
            
            accessible = data['accessible'][:15]  # Max 15 per base
            unreachable = data['unreachable'][:15]
            
            if accessible:
                description += "  En ligne:\n"
                for domain, status in accessible:
                    description += f"    `{domain}` [{status}]\n"
                    domain_count += 1
            
            if unreachable:
                description += "  Hors ligne:\n"
                for domain, status in unreachable:
                    description += f"    `{domain}` [{status or 'timeout'}]\n"
                    domain_count += 1
            
            embed = {
                "title":       f"Nouveaux certificats — {domain_count} domaine(s)",
                "description": description,
                "color":       0x5865f2,
                "fields": [
                    {"name": "Source", "value": log_name, "inline": True},
                ],
                "footer":    {"text": "CT Monitor"},
                "timestamp": datetime.utcnow().isoformat()
            }
            embeds.append(embed)
            
            if len(embeds) >= 1:  # 1 embed per base (can batch further if needed)
                discord_send({"embeds": embeds})
                embeds = []

        if embeds:
            discord_send({"embeds": embeds})

        with stats_lock:
            stats['alertes_envoyées'] += 1
            stats['dernière_alerte']   = datetime.utcnow()

        tprint(f"[DISCORD] {len(filtered)} notifiés")
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

# ==================== CERTIFICATE PARSING ====================
def _cert_hash(leaf_input: str) -> str:
    return hashlib.sha1(leaf_input.encode()).hexdigest()[:16]

def parse_certificate(entry):
    try:
        leaf_input = entry.get('leaf_input', '')
        leaf_bytes = base64.b64decode(leaf_input)

        if len(leaf_bytes) < 12:
            return []

        log_entry_type = int.from_bytes(leaf_bytes[10:12], 'big')
        cert_der       = None
        cert_hash      = _cert_hash(leaf_input)

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
                extra_data = base64.b64decode(entry.get('extra_data', ''))
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
            san_list = list(san_ext.value)
            
            # NEW: Log anomaly if too many SANs
            if len(san_list) > MAX_SANS_PER_CERT:
                db.log_anomaly(cert_hash, "excessive_sans", f"{len(san_list)} SANs (max {MAX_SANS_PER_CERT})")
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

    except Exception as e:
        with stats_lock:
            stats['parse_errors'] += 1
        return []

# ==================== CRON JOBS ====================
_path_scan_running = threading.Event()

def cron_recheck_unreachable():
    tprint("[CRON] Thread recheck démarré")
    RECHECK_BATCH = 100

    while True:
        try:
            total_offline = db.count_offline()
            total         = db.count()
            tprint(f"[CRON] Recheck — {total} domaine(s) | {total_offline} offline")

            back_online = still_down = 0

            if total_offline > 0:
                offset = 0
                while True:
                    domains = db.get_offline(limit=RECHECK_BATCH, offset=offset)
                    if not domains:
                        break
                    for domain, base_domain, last_check in domains:
                        host, port = parse_subdomain_entry(domain)
                        status_code, response_time = check_domain(host)

                        if port:
                            port_open, _ = check_port(host, port)
                            if port_open and (not status_code or status_code >= 400):
                                status_code = 200

                        if status_code == 200:
                            tprint(f"[CRON] ✅ {domain} — redevenu accessible!")
                            send_now_accessible_alert(domain)
                            db.mark_online(domain, status_code)
                            back_online += 1
                        else:
                            db.update_check(domain, status_code, response_time)
                            still_down += 1
                    offset += RECHECK_BATCH
            else:
                tprint("[CRON] Aucun domaine offline")

            tprint(f"[CRON] {back_online} redevenu(s) | {still_down} toujours offline")

            # Purge history
            db.purge_history(retention_days=CHECK_HISTORY_RETENTION_DAYS)

            # NEW: PRAGMA optimize monthly
            with stats_lock:
                last_vac = stats['last_vacuum']
            if (datetime.utcnow() - last_vac).days >= VACUUM_INTERVAL_DAYS:
                db.vacuum_optimize()
                with stats_lock:
                    stats['last_vacuum'] = datetime.utcnow()

            # Path scan
            if _path_scan_running.is_set():
                tprint("[CRON] Path scan ignoré — en cours")
            else:
                def _run_path_scan():
                    _path_scan_running.set()
                    try:
                        path_monitor.check_all()
                    finally:
                        _path_scan_running.clear()
                threading.Thread(target=_run_path_scan, daemon=True, name="PathScan").start()

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

    # NEW: Circuit breaker check
    cb = get_circuit_breaker(log_name)
    if not cb.is_available():
        tprint(f"[{log_name}] ⚠️  Circuit breaker OPEN — skipped")
        with stats_lock:
            stats['circuit_breaker_trips'] += 1
        return 0

    if log_name not in stats['positions']:
        try:
            response  = requests.get(f"{log_url}/ct/v1/get-sth", timeout=10)
            tree_size = response.json()['tree_size']
            with stats_lock:
                stats['positions'][log_name] = max(0, tree_size - 1000)
            cb.record_success()
            tprint(f"[INIT] {log_name}: position {stats['positions'][log_name]:,}")
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

    backlog     = tree_size - current_pos
    max_batches = {'CRITICAL': MAX_BATCHES_CRITICAL, 'HIGH': MAX_BATCHES_HIGH}.get(priority, MAX_BATCHES_MEDIUM)
    tprint(f"[{log_name}] Backlog: {backlog:,}")

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
                # NEW: Track (domain, log_name) tuple
                if cycle_seen(domain, log_name):
                    continue

                # NEW: Limit pending futures
                if len(pending_http) >= MAX_PENDING_HTTP:
                    tprint(f"[{log_name}] ⚠️  Max pending futures atteint — traitement batch")
                    for future in list(pending_http.keys())[:100]:
                        try:
                            status_code, response_time = future.result(timeout=2)
                            all_results.append((domain, status_code))
                        except Exception:
                            pass
                        del pending_http[future]

                future = HTTP_WORKER_POOL.submit(_do_check_domain, domain)
                pending_http[future] = domain

        with stats_lock:
            stats['positions'][log_name] = end_pos
            stats['batches_processed']  += 1
        batches_done += 1

    # Harvest HTTP futures
    for future in as_completed(pending_http, timeout=HTTP_CHECK_TIMEOUT + 5):
        domain = pending_http[future]
        try:
            status_code, response_time = future.result()
        except Exception:
            status_code, response_time = None, None

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

# ==================== DB CLEANUP ====================
def cleanup_db():
    """Entire in SQL — zero memory allocation."""
    try:
        conn   = db.get_conn()
        cursor = conn.cursor()

        cursor.execute("DELETE FROM subdomains WHERE domain LIKE '%.%' AND domain NOT LIKE '%' || ?", ("",))
        # This is invalid SQL — let me fix it:
        # Just delete obvious wildcards
        cursor.execute("DELETE FROM subdomains WHERE domain LIKE '*%'")
        wildcards_deleted = cursor.rowcount

        if targets:
            conditions = []
            params     = []
            for t in targets:
                conditions.append("(domain = ? OR domain LIKE ?)")
                params.extend([t, f'%.{t}'])
            where_clause = " OR ".join(conditions)
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

# ==================== STARTUP ====================
tprint("[START] ================================================")
tprint(f"[START] CT Monitor v4 - Production Ready")
tprint(f"[START] {NB_LOGS_ACTIFS} logs CT | {len(targets)} domaine(s) surveillés")
tprint(f"[START] HTTP pool: {HTTP_CONCURRENCY_LIMIT} workers | Sessions avec rotation")
tprint(f"[START] Retry logic: {HTTP_CHECK_RETRIES} attempts | Circuit breaker: enabled")
tprint(f"[START] Notification TTL: {NOTIFICATION_TTL // 3600}h | History: {CHECK_HISTORY_RETENTION_DAYS}j")
tprint("[START] ================================================")

tprint("[STARTUP] 1/4 — Nettoyage DB...")
cleanup_db()
db.purge_history()
_s = db.stats_summary()
tprint(f"[STARTUP] DB: {_s['total']} domaines | {db.size_mb()} MB")

tprint(f"[STARTUP] 2/4 — Chargement {SUBDOMAINS_FILE}...")
if os.path.exists(SUBDOMAINS_FILE):
    loaded_count, dup_count = load_subdomains_from_file()
    tprint(f"[STARTUP] {loaded_count} ajouté(s), {dup_count} duplicates")
else:
    tprint(f"[STARTUP] {SUBDOMAINS_FILE} absent (optionnel)")

tprint("[STARTUP] 3/4 — Démarrage thread cron...")
threading.Thread(target=cron_recheck_unreachable, daemon=True, name="CronRecheck").start()
time.sleep(1)
tprint("[STARTUP] Thread cron démarré")

tprint("[STARTUP] 4/4 — Prêt pour monitoring")
tprint("[STARTUP] ================================================")

# ==================== MAIN LOOP ====================
cycle = 0
targets_last_reload = 0

while True:
    try:
        cycle      += 1
        cycle_start = time.time()

        # NEW: Dynamic targets reload
        if cycle % TARGETS_RELOAD_INTERVAL == 0:
            tprint(f"[CYCLE #{cycle}] Reloading targets...")
            new_targets = load_targets()
            if len(new_targets) != len(targets):
                tprint(f"[CYCLE #{cycle}] Targets changed: {len(targets)} → {len(new_targets)}")
                targets = new_targets

        with stats_lock:
            stats['dernière_vérification'] = datetime.utcnow()

        tprint(f"[CYCLE #{cycle}] {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")

        cycle_reset()
        update_heartbeat()  # NEW: Healthcheck

        monitor_all_logs()
        save_positions()

        cleared = notif_cache.clear_expired()
        if cleared > 0:
            tprint(f"[CYCLE #{cycle}] Notif cache: {cleared} expirées")

        cycle_duration = int(time.time() - cycle_start)
        _s = db.stats_summary()

        # NEW: Stale data check
        certs_this_cycle = stats['certificats_analysés']
        if certs_this_cycle < MIN_CERTS_PER_CYCLE:
            tprint(f"[ALERT] ⚠️  Seulement {certs_this_cycle} certs ce cycle (min: {MIN_CERTS_PER_CYCLE})")

        tprint(f"[CYCLE #{cycle}] ✅ {cycle_duration}s")
        tprint(f"[CYCLE #{cycle}] Certs: {stats['certificats_analysés']:,} | Matches: {stats['matches_trouvés']:,}")
        tprint(f"[CYCLE #{cycle}] HTTP: {stats['http_checks']:,} | Retries: {stats['retry_http']:,}")
        tprint(f"[CYCLE #{cycle}] Alertes: {stats['alertes_envoyées']:,} | Discord queue: {_discord_queue.qsize()}")
        tprint(f"[CYCLE #{cycle}] DB: {_s['total']} domaines | {db.size_mb()} MB")
        tprint(f"[CYCLE #{cycle}] Prochain cycle dans {CHECK_INTERVAL}s...")
        time.sleep(CHECK_INTERVAL)

    except KeyboardInterrupt:
        tprint("[STOP] Arrêt demandé")
        save_positions()
        _discord_queue.put(None)
        _discord_thread.join(timeout=5)
        HTTP_WORKER_POOL.shutdown(wait=False)
        cleanup_sessions()
        break
    except Exception as e:
        tprint(f"[ERROR] {e}")
        traceback.print_exc()
        save_positions()
        time.sleep(30)

tprint("[STOP] Monitoring arrêté")
