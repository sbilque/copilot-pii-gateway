# Plan : lab d'intégration, filtre absent, isolation des alias

État de départ : `main` au commit 4843ce4 (80 tests unitaires, hooks mitmproxy simulés). Jalon 1 réalisé : voir [le lab](../lab/README.md).

## Constats vérifiés avant de planifier

| Situation | Comportement observé (mitmproxy 12.3.1) | Conséquence |
|---|---|---|
| Politique invalide au démarrage | `Error logged during startup, exiting...`, code de sortie 1, aucun port ouvert | Déjà fermé : le client n'a pas de proxy et échoue |
| Script modifié et cassé pendant l'exécution | Rechargement à chaud, addon déchargé, proxy toujours en écoute, canari en 502 | **Ouvert** : le trafic Copilot traverserait le proxy sans filtre |
| Addon chargé, `guard` pas encore initialisé | Exception dans le hook, refus 403 | Fermé |
| Lanceur Python ajoutant l'addon directement (sans `scripts`) | Politique invalide : sortie en code 1 | Piste retenue pour supprimer le rechargement à chaud |
| Rechargement de la politique | `load()` crée un nouveau `Guard` : mapping perdu, nouveau préfixe | Les alias déjà émis ne sont plus restaurés et, mapping vide, plus vérifiés |
| Mapping | Dictionnaires `aliases`, `reverse` et `known` d'une seule instance `Guard`, sans TTL ni clé de portée | Partagé par toutes les fenêtres et tous les clients du port |

Confirmé par le lab : une passerelle sans addon transmet l'email synthétique en clair à l'amont, et le test N2 échoue.

## Lot A — Lab d'intégration local (Docker)

Cible retenue : lab local Docker Compose sur le Mac mini M4 Pro (Docker Desktop, OrbStack ou Colima), environnement de développement principal. Images multi-architecture (`python:3.12-slim`, `ubuntu/squid`) pour tourner à l'identique en arm64 sur le Mac et en amd64 dans la CI.

### A1. Topologie

```text
tests ──(net: client, internal)──▶ gateway-block / gateway-redact (mitmproxy + addon)
                                              │
                                   (net: egress, internal)
                                              ▼
                                       corp-proxy (Squid)
                                              │
                                   (net: upstream, internal)
                                              ▼
                       fake-copilot (alias DNS : api.business.githubcopilot.com)
```

- Trois réseaux `internal: true` : aucun accès Internet, et le client ne peut joindre ni Squid ni l'amont directement. C'est la preuve qu'aucun chemin de contournement n'existe dans le banc.
- Le nom réel `api.business.githubcopilot.com` est porté par un alias réseau Docker, pour que `target()` et `allowed()` s'appliquent sans modification de code.

### A2. Faux serveur amont `fake-copilot`

- Python avec la bibliothèque standard (`http.server` + `ssl`), pour rester cohérent avec les tests existants.
- Il enregistre chaque corps reçu dans un volume `recordings/`, avec un horodatage et le chemin.
- Il renvoie des réponses scénarisées : JSON Chat Completions, SSE Chat Completions avec `tool_calls`, SSE Responses avec `response.function_call_arguments.delta`, et le format Anthropic avec `partial_json`.
- Mode écho : il recopie les alias reçus dans la réponse, fragmentés à des positions choisies, pour tester la restauration de bout en bout.
- Modes de panne pilotés par en-tête de test : lenteur, coupure au milieu du flux, `gzip` imposé malgré `identity`, alias inconnu, réponse surdimensionnée.

### A3. PKI de test

- Le service `pki` génère une CA de test, le certificat du faux serveur pour `api.business.githubcopilot.com` et la CA mitmproxy, dans un volume Docker : rien n'est écrit dans le dépôt.
- Le gateway fait confiance à cette CA via `ssl_verify_upstream_trusted_ca` ; `ssl_insecure` reste à `false`.
- Le client fait confiance à la CA mitmproxy générée dans le conteneur.

### A4. Proxy d'entreprise de test

| Variante | Mise en œuvre | Ce qu'elle prouve |
|---|---|---|
| `direct_proxy` | Squid sans authentification, `CONNECT` limité au port 443 | Chaînage `upstream:` et absence de sortie directe |
| `auth_proxy` | Squid avec authentification Basic | Gestion d'un 407 et messages d'erreur (substitut, pas NTLM) |
| `integrated_proxy` | Px dans le gateway, puis Squid Basic | Chaînage via Px sur 127.0.0.1:3128 |
| NTLM/Kerberos réel | Non testé dans le lab | Méthode manuelle et non bloquante décrite dans le [guide réseau](network/proxy-enterprise.md) |

### A5. Tests d'intégration

Ils sont écrits dans `lab/test_lab.py` (unittest) et exécutés dans `client-tests`. Le client HTTP passe par le gateway, et chaque test lit les enregistrements de l'amont.

| Id | Scénario | Attendu |
|---|---|---|
| N1 | Prompt neutre | 200 ; octets reçus par l'amont identiques à ceux envoyés |
| N2 | Email synthétique, mode block | 403 ; aucun enregistrement amont |
| N3 | Email synthétique, mode redact | L'amont ne voit que des alias ; la réponse écho est restaurée |
| N4 | SSE Chat, Responses et Anthropic, alias coupés et appels parallèles | Arguments JSON valides et exacts côté client |
| N5 | Secret dans un nom d'outil | 403 dans les deux modes |
| N6 | Corps au-delà de `max_body_bytes` | 413 ; rien côté amont |
| N7 | Canari | `ready: true` depuis le loopback du conteneur, 403 avec `Origin` |
| F1 | Amont arrêté | Erreur côté client, aucune sortie par un autre chemin |
| F2 | Squid arrêté | Erreur, pas de repli direct (garanti par le réseau `internal`) |
| F3 | Script cassé pendant l'exécution | Comportement actuel documenté (test marqué « échec attendu »), puis corrigé par le lot B |
| F4 | Politique invalide au démarrage | Le conteneur gateway s'arrête et le client n'obtient aucun proxy |
| F5 | Worker Presidio tué ou lent | 503, aucun enregistrement amont |
| F6 | Alias inconnu renvoyé par l'amont | 502 |
| F7 | `gzip` imposé par l'amont | Restauration correcte ou refus explicite, jamais d'alias brut |

Règle : chaque test vérifie le corps effectivement reçu par l'amont, pas seulement le code HTTP.

### A6. Outillage

- Fichiers dans `lab/` : `compose.yaml`, `fake_copilot.py`, `squid.conf`, `test_lab.py`, et `Dockerfile` pour le gateway, construit depuis le dépôt pour garder les versions de `requirements.txt`. Le code est copié dans l'image et `make lab-test` reconstruit uniquement les couches modifiées : ce choix fonctionne à l'identique dans le devcontainer (docker-in-docker) et dans la CI, contrairement à un montage de dossier.
- Cibles Make : `lab-up`, `lab-test`, `lab-logs`, `lab-shell`, `lab-down`, et `lab` (cycle complet avec arrêt garanti).
- CI retenue : workflow GitHub Actions sur runner Ubuntu, déclenché sur push et pull request, qui exécute `make check` puis `make lab`. En cas d'échec, il conserve en artefact les journaux et les enregistrements amont (données synthétiques uniquement).

Critère de fin du lot A : `make lab` passe de bout en bout sur le Mac mini et dans la CI, et F3 est le seul échec attendu.

## Lot B — Filtre absent ou non chargé

### B1. Lanceur sans rechargement à chaud

- Nouveau `gateway.py` : il construit le maître mitmproxy, charge `config.yaml` avec le gestionnaire d'options, puis ajoute `CopilotPII` directement. L'addon n'est plus chargé par `scripts`, donc rien n'est surveillé ni rechargé.
- Il refuse de démarrer si `config.yaml` contient encore `scripts` (risque de double chargement) ou si la politique est invalide. Code de sortie non nul dans les deux cas.
- Le lanceur devient le mode de lancement unique : `make run`, le lab et la CI l'utilisent tous, pour que ce qui est testé soit exactement ce qui tourne. `scripts` est retiré de `config.yaml` ; `mitmdump` n'est plus documenté que comme outil de diagnostic.
- Tests : F3 passe (plus aucun rechargement), F4 reste vrai, et un test unitaire couvre le refus de `scripts`.

### B2. Rechargement explicite de la politique

- Le rechargement passe par un redémarrage du processus, pas par la surveillance de fichiers. Le mapping est alors perdu, de façon explicite (voir C2).

### B3. Verrou réseau (défense en profondeur)

Le lanceur ferme le cas du filtre absent dans le processus. Il ne ferme pas celui où VS Code ou un autre processus contourne le gateway.

| Environnement | Mesure à évaluer |
|---|---|
| Banc Docker | Réseaux `internal`, déjà en place dans A1 |
| Linux | nftables : sortie vers le proxy d'entreprise autorisée uniquement pour l'utilisateur système du gateway (`meta skuid`) |
| macOS | pf avec le mot-clé `user` sur les règles TCP sortantes, à valider |
| Windows | Pare-feu Windows par programme vers l'adresse du proxy d'entreprise, à valider avec la sécurité |

Ces règles relèvent du poste et de la politique de l'entreprise. Le dépôt fournit des exemples et une procédure de vérification, pas une application automatique.

### B4. Supervision

- Canari périodique (`launchd`, minuteur `systemd` ou Planificateur de tâches) qui exécute `check_proxy.py`. En cas d'échec, il alerte et peut arrêter le gateway : un gateway arrêté est fermé, un gateway sans filtre ne l'est pas.

Critère de fin du lot B : aucun scénario du banc ne permet un transfert sans analyse, et la procédure de verrou réseau est décrite pour au moins un système, puis vérifiée.

## Lot C — Isolation des correspondances alias/valeurs

### C1. Correctifs immédiats

- En mode redact, la réponse est toujours vérifiée, même si le mapping est vide. Tout motif `__PII_…__` inconnu donne un 502 au lieu d'arriver brut au client. Cela couvre le redémarrage et la perte de mapping.
- Le préfixe d'alias est toujours tiré au hasard à chaque démarrage, ce qui empêche qu'un ancien alias corresponde par hasard à une nouvelle valeur.
- Tests : réponse avec un alias issu d'une instance précédente, et réponse avec un alias bien formé mais inconnu sur un mapping vide.

### C2. Abstraction `MappingStore`

- Elle extrait `aliases`, `reverse` et `known` de `Guard` vers une classe dédiée, avec une clé de portée.
- Durée de vie : TTL d'inactivité par portée, 8 heures par défaut, réglable par `mapping_ttl_s` dans `policy.json` (28800, validé dans `pii_config.py` avec des bornes), capacité par portée (`max_aliases` existant), purge à l'arrêt (`done()`).
- Aucune persistance sur disque par défaut. Une persistance chiffrée ne serait envisagée que si la reprise des états opaques du fournisseur (`previous_response_id`) l'exige, après mesure.
- Expiration : une entrée expirée fait refuser les réponses qui la référencent (502). Elle n'est jamais réattribuée à une autre valeur.

### C3. Choix de la portée

| Portée | Mise en œuvre | Prérequis | Recommandation |
|---|---|---|---|
| Processus | Actuel | Aucun | État actuel |
| Utilisateur du système | Un gateway par utilisateur, sur un port dédié | Port dérivé ou configuré par utilisateur | **Retenue** |
| Profil ou espace de travail VS Code | Un gateway par profil, sur des ports distincts | Paramètres de proxy par profil à valider | Si le besoin est confirmé |
| Conversation | Clé tirée d'un identifiant de requête stable | Identifiant fiable à confirmer, en relevant uniquement les noms d'en-têtes (pas les valeurs) sur un poste autorisé | Seulement si un identifiant fiable est prouvé |

Point de vigilance : le client renvoie l'historique avec les valeurs déjà restaurées, qui sont repseudonymisées à chaque requête. Une portée fine améliore surtout la stabilité des alias et réduit l'exposition en mémoire, pas la confidentialité vis-à-vis du fournisseur.

### C4. Isolation entre utilisateurs d'une même machine

- Le port loopback est joignable par tout utilisateur local. Une authentification du proxy local est ajoutée en option, désactivée par défaut : `make proxy-secret` génère un secret aléatoire dans un fichier local non versionné, et le lanceur l'applique via l'option `proxyauth` de mitmproxy si ce fichier existe.
- La prise en charge par VS Code (identifiants dans `http.proxy` ou invite) est vérifiée dans le lab avant d'être documentée.
- Le lab teste les deux configurations : sans secret, comportement actuel ; avec secret, un client sans identifiants est refusé (407) avant toute analyse.

Critère de fin du lot C : tests unitaires et d'intégration pour l'expiration, le redémarrage, la portée par utilisateur et le refus d'un client non autorisé. La documentation et l'ADR-002 sont mis à jour.

## Ordre et jalons

| Jalon | Contenu | Dépend de | Taille |
|---|---|---|---|
| J1 | A1 à A4 et A6 : lab minimal, N1 à N3, direct_proxy, CI, devcontainer | — | M, **fait** |
| J2 | A5 complet, avec F3 marqué « échec attendu » | J1 | M, **fait** |
| J3 | C1 : vérification systématique des alias | J1 | S |
| J4 | B1 et B2 : lanceur ; F3 devient un succès | J2 | S |
| J5 | C2 et C3 : `MappingStore` et portée par utilisateur | J3 | M |
| J6 | C4 et B4 : authentification du proxy local et supervision | J5 | M |
| J7 | B3 : verrou réseau documenté et vérifié sur un système | J4 | M |
| J8 | NTLM/Kerberos : méthode manuelle documentée, sans test automatisé | — | S, **fait** |

Chaque jalon donne un commit séparé avec ses tests, `make check` et `make lab` au vert, et la mise à jour du handoff et de l'ADR concerné.

## Décisions prises (2026-11-05)

| Question | Décision |
|---|---|
| Hôte du banc | Lab local Docker sur le Mac mini, environnement de développement principal |
| Mode de lancement | Lanceur `gateway.py` partout (lab, CI, `make run`) ; `mitmdump` réservé au diagnostic |
| Portée des alias | Par utilisateur du système |
| TTL d'inactivité | 8 heures par défaut, réglable par `mapping_ttl_s` |
| Mot de passe du proxy local | Optionnel, désactivé par défaut |
| CI | Oui : GitHub Actions avec `make check` et `make lab` |

| NTLM/Kerberos | Pas de test dans le lab ; méthode manuelle documentée, non bloquante |
| Environnement de développement | Devcontainer (Python 3.12, make, docker-in-docker), avec `make setup` à la création |
