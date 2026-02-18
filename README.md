# CT Monitor

Surveille les **Certificate Transparency Logs** en temps réel pour détecter les nouveaux sous-domaines émis pour vos domaines cibles, vérifie leur accessibilité HTTP/HTTPS, et alerte sur Discord.

---

## Structure du projet

```
ct-monitor/
├── ct_monitor.py       ← Script principal
├── Dockerfile
├── docker-compose.yml
├── domains.txt         ← Vos domaines cibles (un par ligne)
├── .env                ← Variables d'environnement (à créer depuis .env.example)
└── .env.example
```

Les fichiers optionnels suivants sont à placer dans le volume `/app/data` (monté sur le VPS) :
- `subdomains.txt` — sous-domaines à monitorer manuellement dès le démarrage
- `paths.txt` — URLs spécifiques à vérifier toutes les 5 minutes (ex: `/admin`, `/.env`)

---

## Installation

### 1. Configurer les domaines cibles

Éditer `domains.txt` :
```
exemple.com
monsite.fr
```

### 2. Configurer le webhook Discord

```bash
cp .env.example .env
# Éditer .env et renseigner DISCORD_WEBHOOK
```

### 3. Lancer

```bash
docker-compose up -d --build
```

### 4. Voir les logs

```bash
docker logs certstream-monitor -f
```

---

## Fonctionnement

| Étape | Description |
|-------|-------------|
| 1 | Interroge 28 CT logs en parallèle (Google, Cloudflare, DigiCert, Sectigo, Let's Encrypt, TrustAsia) |
| 2 | Parse chaque certificat TLS (x509 et pre-certificates) pour extraire CN et SANs |
| 3 | Compare avec `domains.txt` — tout sous-domaine matché est retenu |
| 4 | Vérifie l'accessibilité HTTP/HTTPS avec suivi des redirections |
| 5 | Envoie un embed Discord groupé par domaine de base |
| 6 | Stocke en SQLite les domaines **inaccessibles** (timeout ou 5xx) |
| 7 | Cron toutes les 5 min : recheck les inaccessibles → alerte Discord si retour en ligne |

---

## Persistance des données

La base SQLite et les positions CT sont dans le volume Docker `ct-data`, monté sur :
```
/var/lib/docker/volumes/ct-data/_data/
├── ct_monitoring.db    ← Base SQLite (domaines inaccessibles + historique)
├── ct_positions.json   ← Positions dans chaque CT log (reprise sans perte)
├── subdomains.txt      ← (optionnel) sous-domaines manuels
└── paths.txt           ← (optionnel) URLs à surveiller
```

Pour récupérer la base :
```bash
cp /var/lib/docker/volumes/ct-data/_data/ct_monitoring.db ./backup.db
```

> ⚠️ Ne jamais faire `docker-compose down -v` — cela supprime les volumes et donc la DB.

---

## Variables d'environnement

| Variable | Obligatoire | Description |
|----------|-------------|-------------|
| `DISCORD_WEBHOOK` | ✅ | URL du webhook Discord pour les alertes |
| `TZ` | Non | Fuseau horaire (défaut: UTC) |

---

## Améliorations appliquées vs version originale

- **Redirections suivies** (`allow_redirects=True`) — les 301/302 ne sont plus considérés comme inaccessibles
- **Pool de connexions SQLite** par thread — plus d'ouverture/fermeture à chaque requête
- **Hash stable** avec `hashlib.md5` au lieu de `hash()` (non déterministe entre process Python)
- **Warnings SSL supprimés** — logs propres sans spam `InsecureRequestWarning`
- **Double déclarations supprimées** — config propre et sans redondance
- **Serveur HTTP supprimé** — inutile, healthcheck Docker remplacé par `pgrep`
- **Backlog loggé** — visible dans les logs à chaque cycle par log CT
