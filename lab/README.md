# Lab d'integration local

Banc Docker pour tester la passerelle avec un vrai mitmproxy, un vrai proxy d'entreprise (Squid) et un faux serveur Copilot. Donnees synthetiques uniquement ; aucun acces Internet depuis les conteneurs.

## Prerequis

- Docker avec Compose v2 : Docker Desktop, OrbStack ou Colima sur le Mac ; Docker Engine sous Linux.
- Ou le devcontainer du depot (`.devcontainer/`), qui fournit Python 3.12, make et Docker (docker-in-docker).

Images multi-architecture : arm64 sur le Mac, amd64 dans la CI.

## Commandes

| Commande | Effet |
|---|---|
| `make lab` | Cycle complet : demarrage, tests, collecte en cas d'echec, arret |
| `make lab-up` | Construit les images et recree tous les conteneurs (etat propre) |
| `make lab-test` | Reconstruit si le code a change, lance les tests, la verification de demarrage (F4) puis le verrou reseau (J7) |
| `make lab-logs` | Suit les journaux |
| `make lab-shell` | Shell dans la passerelle redact |
| `make lab-collect` | Copie journaux, enregistrements amont et journal Squid dans `lab/out/` |
| `make lab-down` | Arrete le lab et supprime ses volumes |

Le code est copie dans l'image ; le cache Docker limite la reconstruction aux couches modifiees. Variables : `DOCKER` (ex. `podman`), `LAB_FILES` (fichiers compose supplementaires), `LAB_BUILD` (vide pour ne pas reconstruire).

## Topologie

```text
tests ──(client)──▶ gateway-* ──(egress)──▶ corp-proxy (Squid) ──(upstream)──▶ fake-copilot
```

| Passerelle | Role |
|---|---|
| `gateway-block` | Politique du depot, mode block |
| `gateway-redact` | Mode redact, plus un literal avec guillemet et antislash (echappement JSON des alias) |
| `gateway-fresh` | Mode redact, ne recoit jamais de donnee sensible : mapping toujours vide (C1) |
| `gateway-ttl` | Mode redact, mapping purge apres 3 s d'inactivite (J5) |
| `gateway-auth` | Mode block, mot de passe du proxy local (secret synthetique du lab) (J6) |
| `gateway-noproxy` | Proxy amont introuvable (F2) |
| `gateway-presidio` | Detecteur externe factice (`fake_worker.py` via `lab/fake_python.sh`), delai 1 s (F5) |
| `gateway-hot` | Code lance depuis le volume `hot`, casse pendant l'execution par les tests (F3) |
| `startup-check` | Profil `faults`, sans reseau : politique invalide puis `scripts` dans la configuration, doit refuser de demarrer (F4) |

`lab/gateway.sh` lit `LAB_MODE`, `LAB_POLICY_PATCH` (JSON fusionne dans `policy.json`), `LAB_UPSTREAM`, `LAB_HOT_DIR`, `LAB_ADD_SCRIPTS` et `LAB_PROXY_AUTH`, puis lance `gateway.py`. Le healthcheck des passerelles execute `check_proxy.py` : une passerelle n'est saine que si l'addon repond au canari.

- `pki` genere une CA de test, le certificat de `api.business.githubcopilot.com` et la CA mitmproxy dans un volume.
- `fake-copilot` porte le vrai nom d'hote par alias reseau, enregistre chaque corps recu (`x-lab-id`) et repond selon l'en-tete `x-lab-scenario` : `echo`, `gzip-echo`, `unknown-alias`, `sse-chat`, `sse-responses`, `sse-anthropic`. Les flux SSE renvoient les alias recus, coupes entre evenements, dans le texte et dans trois appels d'outils entrelaces.
- `corp-proxy` n'autorise que `CONNECT` 443 vers `*.githubcopilot.com`.
- Les passerelles sont lancees par `gateway.py` (addon integre) avec `policy.json` du depot (mode force par `LAB_MODE`) et `lab/mitmproxy.yaml`, avec verification TLS de l'amont.
- Trois reseaux `internal` : le client ne joint que les passerelles, et rien ne sort vers Internet.

## Scenarios couverts

| Id | Verification |
|---|---|
| N1 | Prompt neutre : octets recus par l'amont identiques aux octets envoyes |
| N2 | Email synthetique en mode block : 403, aucun corps recu par l'amont |
| N3 | Email, hote interne et IP privee en mode redact : l'amont ne voit que des alias, le client recoit les valeurs restaurees |
| N4 | SSE Chat Completions, Responses et Anthropic : alias coupes entre evenements et appels d'outils paralleles ; le client reconstruit les valeurs d'origine et des arguments JSON valides |
| N5 | Jeton synthetique dans un nom d'outil : 403 dans les deux modes, rien recu par l'amont |
| N6 | Corps au-dela de `max_body_bytes` : 413, rien recu par l'amont |
| N7 | Canari appele depuis le reseau client, avec ou sans `Origin` : 403 |
| F1 | Amont introuvable : 502, rien enregistre |
| F2 | Proxy d'entreprise injoignable : 502, aucune sortie directe |
| F3 | Code casse pendant l'execution : rien n'est recharge, le filtre reste actif (403, rien recu par l'amont) |
| F4 | Politique invalide ou `scripts` au demarrage : la passerelle refuse de demarrer |
| F5 | Detecteur lent puis plante : 503 sans transfert, puis reprise apres redemarrage du worker |
| F6 | Alias inconnu dans la reponse : 502, aucun alias renvoye au client |
| F7 | Reponse `gzip` : restauree ou refusee explicitement, jamais d'alias brut |
| C1 | Mapping vide : alias d'une autre instance ou alias inconnu -> 502 sans alias renvoye ; reponse neutre transmise |
| J5 | Alias expire apres inactivite : 502 sans valeur ni alias renvoye ; le meme alias n'est jamais reemis |
| J6 | Client sans identifiants ou avec de mauvais identifiants : 407 avant analyse ; avec le secret, filtrage normal |
| J7 | Verrou `network-lock/linux.nft` (nftables reel, service `lock`) : client et root refuses vers Squid, utilisateur de la passerelle accepte, requete via la passerelle 200 |
| I1, I2 | Squid et l'amont injoignables depuis le reseau client |

Les tests lisent ce que l'amont a reellement recu. Controles par mutation : une passerelle sans addon (`mitmdump` seul) fait echouer N2, et `gateway-hot` lancee avec `mitmdump` et `scripts` fait echouer F3.

## Limites

- Pas d'authentification sur Squid, pas de NTLM/Kerberos : voir la methode manuelle du [guide reseau](../docs/network/proxy-enterprise.md).
- F5 utilise un detecteur factice : Presidio reel n'est pas installe dans l'image du lab.
- Squid echoue en 5 s sur un nom introuvable (`dns_timeout`, reglage du lab).
- Les reseaux `internal` reposent sur les regles de Docker ; le verrou du poste est verifie a part (J7).
- Le service `lock` exige nftables dans le noyau. Dans un bac a sable sans nf_tables, `LAB_LOCK_OPTIONAL=1` le fait ignorer ; la CI l'execute toujours.
