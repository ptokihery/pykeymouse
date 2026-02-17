OBJECTIF

Créer en Go un logiciel production-ready permettant :

Windows = capture clavier + souris USB

Linux = serveur cible unique

Partage clavier + souris

Très faible latence (LAN < 5ms)

Sécurité forte

Session expirée

Résilience réseau

Mapping clavier complet

Injection Linux via /dev/uinput

Le système doit être stable, sécurisé, utilisable en environnement professionnel interne.

RÔLES
Windows

Capture Raw Input (pas hook simplifié)

Lecture scancode hardware réel

Gestion flags extended (E0 / E1)

Capture souris (mouvement relatif, clic, molette)

Encodage binaire compact

Connexion TLS persistante vers Linux

Reconnexion automatique

Heartbeat régulier

Mode configurable : keyboard only / mouse only

Linux

Serveur TLS 1.3

Authentification password challenge-response

Génération session token temporaire

Expiration session configurable

Vérification HMAC par message

Protection anti-replay (counter monotonic)

Injection clavier + souris via uinput

Nettoyage propre si crash ou déconnexion

Refuser connexions multiples simultanées

SÉCURITÉ REQUISE
Transport

TLS 1.3 uniquement

Validation certificat

Option certificate pinning

Authentification

Password stocké hashé (bcrypt)

Serveur envoie nonce

Client répond HMAC(password_hash, nonce)

Serveur valide

Serveur génère clé session

Protection messages

Chaque événement contient :

Counter monotonic

Timestamp

Payload

HMAC(session_key, payload + counter + timestamp)

Rejeter si :

Counter réutilisé

Timestamp hors fenêtre (±5s)

HMAC invalide

Session expirée

PERFORMANCE & LATENCE

Exigences :

Connexion TCP persistante

Désactivation Nagle (NoDelay)

Format binaire fixe

Pas de JSON

Pas de compression

Pas de reconnexion par événement

Injection immédiate côté Linux

Buffer minimal

Agrégation micro-burst souris (≤1ms)

Objectif :

LAN câble : 1–3ms

WiFi : <8ms

PROTOCOLE BINAIRE

Structure fixe compacte :

Type (1 byte)

Flags (1 byte)

Code (2 bytes)

Value (4 bytes)

Counter (8 bytes)

Timestamp (8 bytes)

HMAC (32 bytes)

Types :
1 = key
2 = mouse_move
3 = mouse_button
4 = wheel
5 = heartbeat

MAPPING CLAVIER (OBLIGATOIRE)

Mapping complet Windows ScanCode → Linux input-event-codes

Support touches standard

Pavé numérique

Touches étendues

Ctrl gauche/droite distincts

AltGr

Windows key

F1–F12

Support layouts indépendants (scancode hardware, pas caractère ASCII)

Ne jamais transmettre caractères.
Toujours transmettre scancode normalisé.

SOURIS

Mouvement relatif (REL_X / REL_Y)

Clic gauche/droite/milieu

Molette verticale

Option désactivation souris

Pas de position absolue

SESSION & EXPIRATION

Timeout configurable (ex: 10 min)

Expiration si inactivité

Re-auth obligatoire après expiration

Kill session si HMAC invalide

Un seul client autorisé

RÉSILIENCE

Reconnexion automatique côté Windows

Heartbeat toutes les X secondes

Détection déconnexion rapide

Nettoyage uinput si client perdu

Gestion SIGTERM propre

Refus flood

CONFIGURATION

Paramètres configurables :

Port

Activation clavier

Activation souris

Timeout session

IP autorisée

Certificat TLS

Clé TLS

Password hash

EXIGENCES LINUX

Module uinput actif

Permissions sécurisées (pas chmod 666)

Règle udev propre

Service démarrable automatiquement

EXIGENCES WINDOWS

Utiliser Raw Input API

Thread séparé capture input

Thread séparé réseau

Gestion propre fermeture programme

Pas de dépendance abandonnée

TESTS REQUIS

Test latence

Test multi-touches simultanées

Test souris mouvement rapide

Test invalid password

Test replay attack

Test session expiration

Test reconnexion

Test charge continue 8h

OBJECTIF FINAL

Un mini logiciel type InputLeap :

Stable

Sécurisé

Faible latence

Résistant

Utilisable quotidiennement en bureau

Pas un prototype.
Pas un snippet.
Un vrai outil interne propre.
IMPLEMENTATION NOTES

- Go module at repo root. Commands: cmd/pykeymouse-server (Linux) and cmd/pykeymouse-client (Windows).
- Protocol frames are 56 bytes, big-endian, HMAC-SHA256 per message.
- Handshake uses nonce challenge-response, session key, and expiry.
- Windows uses Raw Input scan codes; Linux injects via /dev/uinput.

BUILD

- Linux: go build ./cmd/pykeymouse-server
- Windows: go build ./cmd/pykeymouse-client

CONFIG

- Example configs: configs/server.json and configs/client.json.
- Generate a bcrypt hash with cmd/pykeymouse-hash and copy it to both configs.
- Set TLS cert/key and optional CA or pin.

CERTS

Self-signed:
go run ./cmd/pykeymouse-cert -mode self -out-dir certs -hosts "192.168.1.10,pykeymouse"

CA-signed (creates ca.key/ca.crt and signs server cert):
go run ./cmd/pykeymouse-cert -mode ca -out-dir certs -hosts "192.168.1.10,pykeymouse"

The command prints the exact server/client config values (paths and optional pin).

RUN

- Linux: ensure uinput is available and apply linux/udev/99-pykeymouse-uinput.rules.
- Windows: run pykeymouse-client with the client config.

TESTS

- See docs/tests.md and cmd/pykeymouse-sim.

SERVER GUIDE (Linux)

1. Build:
   go build -o /usr/local/bin/pykeymouse-server ./cmd/pykeymouse-server
2. Create a service user:
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin pykeymouse
3. Enable uinput access:
   sudo cp linux/udev/99-pykeymouse-uinput.rules /etc/udev/rules.d/
   sudo udevadm control --reload-rules
   sudo udevadm trigger
4. Generate TLS certs:
   go run ./cmd/pykeymouse-cert -mode self -out-dir /etc/pykeymouse -hosts "192.168.1.10,pykeymouse"
5. Generate bcrypt hash:
   go run ./cmd/pykeymouse-hash
6. Configure:
   cp configs/server.json /etc/pykeymouse/server.json
   Edit /etc/pykeymouse/server.json:
   - tls.cert_path = "/etc/pykeymouse/server.crt"
   - tls.key_path  = "/etc/pykeymouse/server.key"
   - auth.password_hash_bcrypt = "<bcrypt hash>"
7. Install systemd unit:
   sudo cp linux/systemd/pykeymouse-server.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now pykeymouse-server

CLIENT GUIDE (Windows)

1. Build:
   go build -o pykeymouse-client.exe ./cmd/pykeymouse-client
2. Copy certs:
   Copy server.crt (self) or ca.crt (CA mode) from the server to the client.
3. Generate bcrypt hash:
   go run ./cmd/pykeymouse-hash
4. Configure:
   Copy configs/client.json next to pykeymouse-client.exe and edit:
   - server_addr = "SERVER_IP:8443"
   - tls.ca_cert_path = "C:\\path\\to\\server.crt" (self) or "C:\\path\\to\\ca.crt"
   - auth.password_hash_bcrypt = "<same bcrypt hash as server>"
5. Run:
   pykeymouse-client.exe -config configs\\client.json
