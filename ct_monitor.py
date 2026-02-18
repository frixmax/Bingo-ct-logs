"""
PATCH — Détection intelligente des faux positifs dans PathMonitor
Remplace is_waf_block() et check_path() dans le script principal.
"""

# ==================== HELPERS DETECTION ====================

# Extensions / paths dont on connaît le type de contenu attendu
PATH_CONTENT_EXPECTATIONS = {
    # Path pattern → (type attendu, mots-clés requis dans le body)
    '.env':          ('text/plain env',  ['=', 'KEY', 'SECRET', 'PASSWORD', 'TOKEN', 'DB_', 'APP_']),
    '.env.backup':   ('text/plain env',  ['=', 'KEY', 'SECRET', 'PASSWORD', 'TOKEN']),
    '.env.local':    ('text/plain env',  ['=', 'KEY', 'SECRET']),
    '.git/config':   ('text git config', ['[core]', '[remote', 'repositoryformatversion']),
    'wp-config.php': ('php wordpress',   ['DB_NAME', 'DB_PASSWORD', 'DB_HOST', 'table_prefix', 'define(']),
    'backup.sql':    ('sql dump',        ['INSERT INTO', 'CREATE TABLE', 'DROP TABLE', '--', 'mysqldump']),
    'actuator/env':  ('json spring',     ['"activeProfiles"', '"propertySources"', '"systemProperties"', '"name":']),
    'actuator/health': ('json spring',   ['"status"', '"UP"', '"DOWN"']),
    'api/v1/users':  ('json api',        ['"id"', '"email"', '"username"', '"users"', '[']),
    'phpinfo.php':   ('php info',        ['PHP Version', 'php_info', 'phpinfo']),
    'server-status': ('apache status',   ['Apache Server Status', 'requests currently being processed']),
}

# Indicateurs structurels d'une page de login/auth — indépendants des textes
AUTH_PAGE_INDICATORS = [
    # Formulaires d'auth
    ('form', 'action', ['/oauth2/', '/auth/', '/login', '/signin', '/sso/', '/saml/', '/oidc/']),
    # Meta redirect vers IdP
    ('meta', 'http-equiv', ['refresh']),
]

# Patterns HTML qui signalent une page de login, indépendamment de la langue
AUTH_HTML_PATTERNS = [
    # OAuth / SSO
    'oauth2/start',
    'oauth2/sign_in',
    '/oauth2/callback',
    '/oauth2/static/',
    'oauth2-proxy',
    # Formulaires génériques de login
    'type="password"',
    "type='password'",
    # Redirections auth standard
    'oidc/login',
    'saml/login',
    '/sso/login',
    '/auth/login',
    # Tokens CSRF courants (indique un formulaire de login)
    'name="csrf_token"',
    'name="_token"',
    'name="authenticity_token"',
    # Fournisseurs SSO enterprise
    'login.microsoftonline.com',
    'aadcdn.msftauth.net',
    'accounts.google.com',
    'okta.com/login',
    'ping.identity',
    'auth0.com',
    'onelogin.com',
    # OAuth2 Proxy spécifique
    'signin-button',
    '/oauth2/static/css/',
    '/oauth2/static/images/',
    # Azure AD
    'ConvergedSignIn',
    'estsauth',
    # Generic
    'id="login-form"',
    'id="loginForm"',
    'class="login-form"',
    'id="sign-in-form"',
]

# Patterns qui indiquent une SPA "catch-all" (retourne index.html pour tout)
SPA_CATCHALL_INDICATORS = [
    # React/Vue/Angular SPA typiques
    'id="root"',
    'id="app"',
    'id="__next"',          # Next.js
    'id="__nuxt"',          # Nuxt.js
    # Bundles JS avec hash (webpack, vite)
    # détecté dynamiquement via check_path_content_coherence()
]


def is_auth_page(body: str) -> tuple[bool, str]:
    """
    Détecte sémantiquement une page d'authentification/login.
    Ne se base pas sur des textes en langue naturelle, mais sur la structure HTML.
    Retourne (True, raison) si c'est une page d'auth.
    """
    body_low = body.lower()

    # 1. Patterns HTML d'auth directs
    for pattern in AUTH_HTML_PATTERNS:
        if pattern.lower() in body_low:
            return (True, f"auth_pattern: {pattern}")

    # 2. Formulaire avec action vers un endpoint d'auth
    import re
    form_actions = re.findall(r'<form[^>]+action=["\']([^"\']+)["\']', body_low)
    for action in form_actions:
        for keyword in ['/oauth', '/auth', '/login', '/signin', '/sso', '/saml', '/oidc']:
            if keyword in action:
                return (True, f"form_action_auth: {action}")

    # 3. Meta refresh vers un IdP
    meta_refresh = re.findall(r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\'][^"\']+url=([^"\'&\s]+)', body_low)
    for url in meta_refresh:
        for keyword in ['/oauth', '/auth', '/login', '/sso', '/saml', 'microsoftonline', 'google', 'okta']:
            if keyword in url:
                return (True, f"meta_refresh_auth: {url}")

    # 4. Script qui poste un message 3DS/auth (Vodacom pattern)
    # Détecte les SPAs payment/auth qui catchent tout
    if 'postmessage' in body_low and ('3ds' in body_low or 'payment' in body_low):
        return (True, "spa_payment_auth: postMessage 3DS/payment detected")

    return (False, None)


def is_spa_catchall(body: str, requested_path: str) -> tuple[bool, str]:
    """
    Détecte si le serveur retourne une SPA générique pour un path
    qui devrait retourner un type de contenu spécifique.

    Logique : si le path demandé implique un contenu non-HTML
    (SQL, env, config, JSON API...) mais que le retour est du HTML,
    c'est forcément un catch-all.
    """
    # Extensions / segments qui NE doivent PAS retourner du HTML
    non_html_paths = ['.sql', '.env', '.bak', '.backup', '.conf', '.config',
                      '.yml', '.yaml', '.ini', '.log', '.gz', '.tar', '.zip']

    path_low = requested_path.lower()

    # Si le path demande explicitement un fichier non-HTML
    for ext in non_html_paths:
        if path_low.endswith(ext):
            # Si le body est du HTML → catch-all certain
            if '<html' in body.lower() or '<!doctype' in body.lower():
                return (True, f"html_for_non_html_path: {ext} path returned HTML")

    # Indicateurs SPA classiques dans le body
    body_low = body.lower()
    for indicator in SPA_CATCHALL_INDICATORS:
        if indicator in body_low:
            # Double vérification : le titre de la page ne correspond pas au path
            import re
            titles = re.findall(r'<title[^>]*>([^<]+)</title>', body_low)
            if titles:
                title = titles[0].strip()
                # Si le titre est un nom d'app (pas lié au path demandé) → SPA catch-all
                path_segments = [s for s in path_low.split('/') if s]
                if path_segments and not any(seg in title for seg in path_segments):
                    return (True, f"spa_catchall: {indicator}, title='{title}' unrelated to path")

    return (False, None)


def check_content_coherence(body: str, path: str) -> tuple[bool, str]:
    """
    Vérifie que le contenu retourné est cohérent avec le path demandé.
    
    Si on demande /backup.sql et qu'on reçoit du HTML → incohérent.
    Si on demande /actuator/env et qu'on reçoit du JSON Spring → cohérent.
    Si on demande /.env et qu'on reçoit KEY=value → cohérent.

    Retourne (is_coherent, reason).
    """
    path_low = path.lower()
    body_sample = body[:3000]  # Analyser seulement le début

    for pattern, (expected_type, keywords) in PATH_CONTENT_EXPECTATIONS.items():
        if pattern in path_low:
            # Vérifier si au moins UN des mots-clés attendus est présent
            found_keywords = [kw for kw in keywords if kw.lower() in body_sample.lower()]
            if not found_keywords:
                return (False, f"content_mismatch: path '{pattern}' expected {expected_type} keywords {keywords[:3]}, none found")
            return (True, f"content_match: found {found_keywords[:2]}")

    # Pas de règle spécifique pour ce path → on fait confiance
    return (True, "no_specific_rule")


def is_waf_block(response) -> tuple[bool, str]:
    """
    VERSION AMÉLIORÉE — Détecte les pages de blocage, d'auth et les catch-all SPA.
    
    Détections:
    1. WAF classiques (Cloudflare, Incapsula, ModSecurity...)
    2. Pages d'authentification/login (OAuth2, SSO, SAML, Azure AD...)
    3. SPAs catch-all (React/Vue/Angular qui retournent index.html pour tout)
    """
    headers      = {k.lower(): v.lower() for k, v in response.headers.items()}
    content_type = headers.get('content-type', '')

    if 'text/html' not in content_type:
        return (False, None)

    try:
        body     = response.text[:8000]
        is_short = len(body) < 2000

        # --- WAF body signatures (inchangées) ---
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
            'NotFoundException',
            'not found',
            'endpoint not found',
            'resource not found',
        ]

        body_low = body.lower()
        for sig in WAF_BLOCK_BODY_SIGNATURES:
            if sig.lower() in body_low:
                return (True, f"waf_block: '{sig}'")

        # Cloudflare JS challenge
        if is_short and 'cloudflare' in body_low and ('challenge' in body_low or 'captcha' in body_low):
            return (True, "waf_block: cloudflare challenge")

        # Incapsula
        if is_short and '_incapsula_resource' in body_low and 'noindex' in body_low:
            return (True, "waf_block: incapsula")

        # --- NOUVEAU : Détection page auth/login ---
        is_auth, auth_reason = is_auth_page(body)
        if is_auth:
            return (True, f"auth_page: {auth_reason}")

    except Exception:
        pass

    return (False, None)


def check_path(self, url: str) -> tuple:
    """
    VERSION AMÉLIORÉE de PathMonitor.check_path().
    
    Ajoute après la détection WAF existante :
    - Détection SPA catch-all (body HTML pour path non-HTML)
    - Vérification cohérence contenu/path
    """
    MAX_CONTENT_SIZE = 5 * 1024 * 1024

    from urllib.parse import urlparse
    parsed_path = urlparse(url).path  # ex: /backup.sql, /actuator/env

    try:
        import requests as req
        response = req.get(
            url,
            timeout=HTTP_CHECK_TIMEOUT,
            verify=False,
            allow_redirects=True,
            headers={'User-Agent': 'Mozilla/5.0 (compatible; CTMonitor/1.0)'},
            stream=True
        )
        response_time = int(response.elapsed.total_seconds() * 1000)

        if response.status_code == 200:
            content_type = response.headers.get('Content-Type', '').lower()
            if content_type and 'text/html' not in content_type \
                    and 'application/json' not in content_type \
                    and 'text/plain' not in content_type:
                return (403, None, response_time, f"Invalid Content-Type: {content_type}")

            content_length = response.headers.get('Content-Length', '0')
            try:
                size = int(content_length)
                if size > MAX_CONTENT_SIZE:
                    return (403, None, response_time, f"Content too large ({size} bytes)")
            except Exception:
                pass

            # Détection WAF (inclut maintenant la détection auth/login)
            waf, reason = is_waf_block(response)
            if waf:
                return (403, None, response_time, f"WAF/Auth: {reason}")

            try:
                content = response.text[:MAX_CONTENT_SIZE]

                if not content or len(content) <= 200:
                    return (403, None, response_time, f"Content too small ({len(content)} bytes)")

                # NOUVEAU 1 : SPA catch-all (ex: React qui retourne index.html pour /backup.sql)
                is_catchall, catchall_reason = is_spa_catchall(content, parsed_path)
                if is_catchall:
                    tprint(f"[PATHS FP] {url} → SPA catch-all: {catchall_reason}")
                    return (403, None, response_time, f"SPA catch-all: {catchall_reason}")

                # NOUVEAU 2 : Cohérence contenu/path
                is_coherent, coherence_reason = check_content_coherence(content, parsed_path)
                if not is_coherent:
                    tprint(f"[PATHS FP] {url} → Contenu incohérent: {coherence_reason}")
                    return (403, None, response_time, f"Content mismatch: {coherence_reason}")

                if len(content) <= MAX_CONTENT_SIZE:
                    return (200, content, response_time, None)
                else:
                    return (403, None, response_time, "Content is empty")

            except Exception as e:
                return (None, None, response_time, f"Error reading body: {str(e)[:50]}")

        elif response.status_code == 403:
            return (403, None, response_time, None)

        return (response.status_code, None, response_time, None)

    except req.exceptions.Timeout:
        return (None, None, HTTP_CHECK_TIMEOUT * 1000, "Timeout")
    except Exception as e:
        return (None, None, None, str(e))


# ==================== RÉSUMÉ DES CAS COUVERTS ====================
"""
CAS 1 — TomTom OAuth2 Proxy:
  /actuator/env → HTML avec <form action="/oauth2/start">
  → is_auth_page() détecte 'oauth2/start' dans form action → bloqué ✅

CAS 2 — Vodacom SPA (React payment):
  /backup.sql → HTML (<!doctype html>...)
  → is_spa_catchall() détecte que .sql retourne du HTML → bloqué ✅
  
  /wp-config.php → HTML
  → check_content_coherence() : wp-config.php attend DB_NAME, DB_PASSWORD... 
    aucun keyword trouvé dans le HTML → content mismatch → bloqué ✅

  /.env.backup → HTML
  → is_spa_catchall() : .backup est non-HTML, body est HTML → bloqué ✅

CAS 3 — Vrai positif préservé:
  /.env → "DB_PASSWORD=secret\nAPP_KEY=base64:..."
  → is_spa_catchall(): pas de <html> dans un vrai .env → OK
  → check_content_coherence(): trouve '=' et 'PASSWORD' → cohérent ✅
  → Alerte envoyée ✅
  
  /actuator/env → JSON {"activeProfiles":[],"propertySources":[...]}
  → is_auth_page(): pas de form auth → OK
  → check_content_coherence(): trouve '"activeProfiles"' → cohérent ✅
  → Alerte envoyée ✅
"""
