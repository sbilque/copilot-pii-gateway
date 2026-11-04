# Utiliser le prototype reconstruit

## Portee

Cette version reconstitue les principes du prototype historique, pas son code a l'identique. Elle remplace les 51 tests historiques non disponibles par 31 tests reproductibles. Les hooks HTTP sont simules : aucune integration reelle n'a ete validee.

## Preparation

```bash
python -m venv .venv
# Activer le venv suivant le systeme.
python -m pip install -r requirements.txt
python -m unittest -v
```

En reseau ferme, utiliser les miroirs et procedures de provisionnement approuves. Les versions sont bornees, pas verrouillees par un lock de dependances.

## Configuration

Adapter le proxy amont dans config.yaml. Depuis la racine du projet :

```bash
mitmdump --set confdir=.
```

La configuration inclut deja scripts ; ne pas ajouter -s pour eviter de charger l'addon deux fois. Verifier les options avec `mitmdump --options`.

Pour NTLM/Kerberos, lancer Px avec le serveur d'entreprise explicite et remplacer le mode par `upstream:http://127.0.0.1:3128`. Voir le [guide reseau](network/proxy-enterprise.md).

Installer uniquement le certificat public CA genere par mitmproxy dans le magasin reconnu par Copilot, avec accord de la securite. Ne jamais partager sa cle privee. Garder la verification TLS ; ajouter le bundle CA amont approuve si inspection HTTPS.

Configurer VS Code :

```json
{"http.proxy":"http://127.0.0.1:8080","http.proxyStrictSSL":true}
```

Ce transport est une interception HTTPS, pas la redirection native Headroom. En WSL/SSH/conteneur, verifier le lieu d'execution de l'hote d'extension.

Executer `python check_proxy.py` apres chaque demarrage avant utilisation. Si l'addon echoue au chargement, mitmproxy peut continuer sans filtre : le canari detecte l'absence du filtre mais n'est pas un verrou reseau ni une preuve du bon processus.

## Politique

Mode `block` par defaut. Pour des essais synthetiques uniquement, choisir `redact` dans policy.json puis redemarrer. Pas de mode audit qui laisserait intentionnellement passer les detections.

Adapter patterns et literals. Emails, IPv4 RFC1918, suffixes internes d'exemple et certains secrets sont couverts. Les descriptions d'outils sont analysees sans reecriture ; une detection les bloque. Les noms d'outils contextuels sont preserves. Les blocs signes, les types multimedia reconnus et les gros data: sont refuses.

Presidio facultatif : installer requirements-presidio.txt et un modele spaCy approuve, puis definir presidio_language (ex. fr), presidio_model (ex. fr_core_news_lg) et presidio_score dans policy.json. Aucun telechargement de modele n'est effectue par l'addon lui-meme. Integration non testee ici.

## Limites et validation

- Reponses entierement bufferisees, meme SSE : pas d'affichage progressif, risque de timeout sur longues generations. Les deltas sont regroupes par canal puis le texte restaure est place dans le premier fragment de chaque canal.
- Taille verifiee apres buffering pour corps sans longueur fiable ; pas de plafond memoire global, concurrence non bornee et analyse synchrone.
- Mapping global mono-utilisateur en memoire ; pas de TTL ni isolation par conversation. Redemarrage et historique fournisseur opaque non garantis.
- Detection imparfaite et protocole non exhaustif : contenus encodes ou noms de champs nouveaux peuvent echapper aux classifications.
- Les arguments d'outils JSON sont parses avant restauration pour echapper correctement les guillemets/antislashs. Tester des schemas reels avant toute execution.
- Headers, URLs, GET sans corps, telemetrie, agents cloud, appels MCP directs et contexte obtenu cote serveur non couverts.
- Les domaines non cibles peuvent etre tunnelises sans inspection ; aucune garantie globale anti-fuite sans regles reseau.
- Une erreur de requete donne un 403, une longueur declaree excessive un 413 et une erreur de restauration un 502.
- Ne pas utiliser de dump de flux ni d'autres addons journalisant les corps ou credentials. Garder les CA et configs privees hors Git.

Verifier un prompt neutre, un canari email, le corps sortant, les reponses JSON/SSE, les appels paralleles, les arguments d'outils, le proxy d'entreprise et l'absence de chemin direct de secours. Tous les essais doivent utiliser des donnees synthetiques et des outils sans effets de bord.
