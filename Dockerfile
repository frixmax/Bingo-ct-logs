# syntax=docker/dockerfile:1

FROM python:3.11-slim

# Installation d'outils système utiles (sqlite3 pour maintenance, curl pour healthchecks)
RUN apt-get update && apt-get install -y --no-install-recommends \
    sqlite3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Création d'un utilisateur non-root pour la sécurité
RUN useradd -m -u 1000 monitor

# Répertoire de travail
WORKDIR /app

# Copie et installation des dépendances Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && rm -rf /root/.cache/pip

# Copie du script principal
COPY ct_monitor.py .

# Copie des fichiers de configuration (optionnels)
# On utilise un script shell pour éviter les erreurs si les fichiers n'existent pas
COPY domains.txt .      2>/dev/null || true
COPY paths.txt .        2>/dev/null || true
COPY subdomains.txt .   2>/dev/null || true

# Création du dossier data + heartbeat + attribution des droits
RUN mkdir -p /app/data \
    && touch /tmp/ct_monitor.heartbeat \
    && chown -R monitor:monitor /app /tmp

# Passage en utilisateur non-root
USER monitor

# Healthcheck basé sur le fichier heartbeat (vérifie qu'il est récent < 120s)
# Si le script plante ou gèle, le heartbeat ne se met plus à jour -> Docker restartera le conteneur
HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD test -f /tmp/ct_monitor.heartbeat && test $(($(date +%s) - $(stat -c %Y /tmp/ct_monitor.heartbeat))) -lt 120 || exit 1

# Commande de démarrage
CMD ["python3", "ct_monitor.py"]
