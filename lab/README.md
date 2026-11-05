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
| `make lab-up` | Construit les images et demarre le lab |
| `make lab-test` | Reconstruit si le code a change, puis lance les tests |
| `make lab-logs` | Suit les journaux |
| `make lab-shell` | Shell dans la passerelle redact |
| `make lab-collect` | Copie journaux, enregistrements amont et journal Squid dans `lab/out/` |
| `make lab-down` | Arrete le lab et supprime ses volumes |

Le code est copie dans l'image ; le cache Docker limite la reconstruction aux couches modifiees. Variables : `DOCKER` (ex. `podman`), `LAB_FILES` (fichiers compose supplementaires), `LAB_BUILD` (vide pour ne pas reconstruire).

## Topologie

```text
tests ──(client)──▶ gateway-block / gateway-redact ──(egress)──▶ corp-proxy (Squid) ──(upstream)──▶ fake-copilot
```

- `pki` genere une CA de test, le certificat de `api.business.githubcopilot.com` et la CA mitmproxy dans un volume.
- `fake-copilot` porte le vrai nom d'hote par alias reseau, enregistre chaque corps recu (`x-lab-id`) et repond en echo.
- `corp-proxy` n'autorise que `CONNECT` 443 vers `*.githubcopilot.com`.
- Les passerelles utilisent `copilot_pii.py`, `policy.json` du depot (mode force par `LAB_MODE`) et `lab/mitmproxy.yaml`, avec verification TLS de l'amont.
- Trois reseaux `internal` : le client ne joint que les passerelles, et rien ne sort vers Internet.

## Scenarios couverts

| Id | Verification |
|---|---|
| N1 | Prompt neutre : octets recus par l'amont identiques aux octets envoyes |
| N2 | Email synthetique en mode block : 403, aucun corps recu par l'amont |
| N3 | Email, hote interne et IP privee en mode redact : l'amont ne voit que des alias, le client recoit les valeurs restaurees |
| I1, I2 | Squid et l'amont injoignables depuis le reseau client |

Les tests lisent ce que l'amont a reellement recu. Une passerelle sans addon fait echouer N2 : verifie en retirant `scripts` de la configuration.

## Limites

- Pas d'authentification sur Squid, pas de NTLM/Kerberos : voir la methode manuelle du [guide reseau](../docs/network/proxy-enterprise.md).
- Pas encore de scenarios SSE, de pannes ni de canari depuis le reseau client : jalon 2 du [plan](../docs/plan.md).
- Les reseaux `internal` reposent sur les regles de Docker ; ils ne remplacent pas un verrou reseau sur le poste.
