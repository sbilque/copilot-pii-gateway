# Utiliser le prototype reconstruit

## Portee

Cette version reconstitue les principes du prototype historique, pas son code a l'identique. Elle remplace les 51 tests historiques non disponibles par 108 tests reproductibles. Les hooks HTTP sont simules ; le worker Presidio est teste avec de vrais processus enfants. Aucune integration Copilot reelle n'a ete validee.

## Preparation

Avec make (Python 3.12 minimum, `PYTHON=python3.12` pour en choisir un autre) :

| Cible | Effet |
|---|---|
| `make setup` | venv, mitmproxy, CA locale, compilation, tests, politique et config.yaml |
| `make setup-presidio` | setup puis Presidio et modele spaCy (`PRESIDIO_MODEL=fr_core_news_lg` par defaut) |
| `make px-config`, `make px` | px.ini depuis l'exemple, installation bornee de Px puis lancement |
| `make run`, `make canary` | proxy au premier plan, puis canari depuis un autre terminal |
| `make doctor` | etat de l'environnement et etapes manuelles restantes |
| `make lab` | lab d'integration Docker, voir [lab/README.md](../lab/README.md) |
| `make clean`, `make distclean` | caches, puis venv ; la CA locale est conservee |

`make ca` genere la CA mitmproxy dans le depot (fichiers ignores par Git) sans l'installer dans un magasin systeme. `make config-check` signale les options inconnues et un proxy amont reste sur l'exemple. Le telechargement du modele spaCy passe par `spacy download` : en reseau ferme, installer le modele depuis le miroir approuve.

Sans make :

```bash
python -m venv .venv
# Activer le venv suivant le systeme.
python -m pip install -r requirements.txt
python -m unittest -v
```

En reseau ferme, utiliser les miroirs et procedures de provisionnement approuves. Les versions sont bornees, pas verrouillees par un lock de dependances.

## Configuration

Adapter le proxy amont dans config.yaml. La politique JSON est chargee avec rejet des cles dupliquees et constantes non standard, puis validee dans le coeur avant initialisation de Presidio. Les listes exact_hosts et host_suffixes sont obligatoires (au moins une non vide), avec noms DNS minuscules sans schema, port, wildcard ou point final. Les limites sont des entiers positifs, sauf cache_size qui peut valoir zero ; max_aliases ne peut depasser 999999. Les regex, litteraux, categories bloquees et options Presidio sont controles. SECRET doit rester dans block_entities. Une politique invalide ou absente empeche le demarrage de la passerelle (code de sortie non nul).

Depuis la racine du projet :

```bash
make run    # ou : COPILOT_PII_CONFIG=policy.json python gateway.py --set confdir=.
```

`gateway.py` accepte les options de `mitmdump` et integre l'addon : pas de `scripts` dans config.yaml ni de `-s` (demarrage refuse), pas de rechargement a chaud. Pour changer de politique, redemarrer : le mapping est perdu (ADR-006). `mitmdump` ne sert plus qu'au diagnostic.

Pour NTLM/Kerberos, lancer Px avec le serveur d'entreprise explicite et remplacer le mode par `upstream:http://127.0.0.1:3128`. Voir le [guide reseau](network/proxy-enterprise.md).

Installer uniquement le certificat public CA genere par mitmproxy dans le magasin reconnu par Copilot, avec accord de la securite. Ne jamais partager sa cle privee. Garder la verification TLS ; ajouter le bundle CA amont approuve si inspection HTTPS.

Configurer VS Code :

```json
{"http.proxy":"http://127.0.0.1:8080","http.proxyStrictSSL":true}
```

Ce transport est une interception HTTPS, pas la redirection native Headroom. En WSL/SSH/conteneur, verifier le lieu d'execution de l'hote d'extension.

Executer `python check_proxy.py` apres chaque demarrage avant utilisation. Si l'addon echoue au chargement, mitmproxy peut continuer sans filtre : le canari detecte l'absence du filtre mais n'est pas un verrou reseau ni une preuve du bon processus.

Le canari exerce la politique active sur une copie des mappings et du cache, sans consommer leur capacite. Un corps neutre doit passer ; canary@example.test doit etre bloque par SensitiveDataError en mode block, ou pseudonymise puis restaure exactement en mode redact. La politique doit donc detecter cet email synthetique. Une erreur de taille, de detecteur, de capacite ou de restauration donne 503, pas ready=true. Avec Presidio, la reponse indique aussi l'etat du worker (champ detector) ; ready=true exige un worker pret et un canari analyse par lui.

## Politique

Mode `block` par defaut. Pour des essais synthetiques uniquement, choisir `redact` dans policy.json puis redemarrer. Pas de mode audit qui laisserait intentionnellement passer les detections.

Adapter patterns et literals. Emails, IPv4 RFC1918, suffixes internes d'exemple et certains secrets sont couverts. Les descriptions d'outils sont analysees sans reecriture ; une detection les bloque. Les noms d'outils contextuels sont preserves sauf detection d'une categorie bloquee : ils sont alors refuses, dans les deux modes. Cette exemption conserve les autres PII eventuelles dans ces noms ; ce n'est pas un registre de noms autorises. Les blocs signes, les types multimedia reconnus et les gros data: sont refuses.

Presidio facultatif : installer requirements-presidio.txt et un modele spaCy approuve, puis definir presidio_language (ex. fr), presidio_model (ex. fr_core_news_lg) et presidio_score dans policy.json. Aucun telechargement de modele n'est effectue par l'addon lui-meme.

Presidio tourne dans un processus separe (pii_worker.py) lance au chargement de l'addon ; voir [ADR-005](adr/005-out-of-process-detector.md). Options, toutes validees au chargement :

| Cle | Defaut | Role |
|---|---|---|
| presidio_timeout_ms | 3000 (100 a 60000) | budget par requete, file d'attente comprise ; au-dela, worker tue et relance, requete refusee en 503 |
| presidio_max_chars | 200000 | longueur maximale d'un texte ; au-dela, refus 403 avant analyse |
| presidio_queue | 8 | requetes en attente du worker ; au-dela, refus 503 immediat |
| presidio_max_restarts | 3 | relances tolerees dans la fenetre avant l'etat failed |
| presidio_restart_window_s | 60 | fenetre de comptage des relances |
| presidio_python | null | interpreteur du worker ; par defaut celui de mitmproxy |

Pendant le chargement du modele (plusieurs secondes) et apres chaque relance, les requetes sont refusees en 503 : attendre que check_proxy.py rapporte ready. Valeurs par defaut a mesurer sur le poste cible. Teste avec en_core_web_sm ; modeles francais non testes ici.

## Limites et validation

- Reponses entierement bufferisees, meme SSE : pas d'affichage progressif, risque de timeout sur longues generations. Les deltas sont regroupes par canal puis le texte restaure est place dans le premier fragment de chaque canal.
- Taille verifiee apres buffering pour corps sans longueur fiable ; pas de plafond memoire global. La file Presidio est bornee, mais pas la concurrence des flux sans analyse lente.
- Mapping global mono-utilisateur en memoire ; pas de TTL ni isolation par conversation. Redemarrage et historique fournisseur opaque non garantis.
- Detection imparfaite et protocole non exhaustif : contenus encodes ou noms de champs nouveaux peuvent echapper aux classifications.
- Les chaines arguments et partial_json sont parsees avant restauration. Les evenements Responses response.function_call_arguments.delta sont explicitement classes comme arguments JSON, y compris avec le seul champ SSE event ; item_id ou output_index est requis pour identifier le canal. Les tests couvrent guillemets, antislashs, retours ligne, toutes les positions de coupure d'un exemple et deux appels paralleles. Cela ne prouve pas la couverture de tous les schemas ni la stabilite des chemins JSON entre evenements ; tester des captures synthetiques representatives avant toute execution.
- En mode redact, l'addon verifie chaque reponse, meme avec un mapping vide : tout motif `__PII_` (y compris via echappements `\u` en JSON ou SSE) passe par la restauration stricte et un alias inconnu donne 502. Le prefixe d'alias est tire au hasard a chaque instance de `Guard`. En mode block, les reponses ne sont pas verifiees.
- Headers, URLs, GET sans corps, telemetrie, agents cloud, appels MCP directs et contexte obtenu cote serveur non couverts.
- Les domaines non cibles peuvent etre tunnelises sans inspection ; aucune garantie globale anti-fuite sans regles reseau.
- Une erreur de requete donne un 403, un detecteur indisponible, sature ou en depassement un 503, une longueur declaree excessive un 413 et une erreur de restauration un 502.
- Ne pas utiliser de dump de flux ni d'autres addons journalisant les corps ou credentials. Garder les CA et configs privees hors Git.

Verifier un prompt neutre, un canari email, le corps sortant, les reponses JSON/SSE, les appels paralleles, les arguments d'outils, le proxy d'entreprise et l'absence de chemin direct de secours. Tous les essais doivent utiliser des donnees synthetiques et des outils sans effets de bord.

## Travaux restants

1. Ajouter et executer une integration locale avec mitmproxy reel, un serveur de test et un proxy amont ; couvrir les pannes et verifier le corps effectivement transmis.
2. Mesurer le worker Presidio sur le poste cible (chargement, latence p50/p95, memoire) et ajuster ses valeurs par defaut ; tester les modeles francais.
3. Borner la memoire avant buffering et la concurrence ; definir l'isolation et la duree de vie des mappings.
4. Decider explicitement si le streaming incremental SSE doit etre reintroduit, avec adaptateurs par protocole et tests des evenements terminaux et canaux paralleles.
5. Ajouter une supervision et un verrou reseau pour l'absence du filtre ; le canari seul ne ferme pas ce risque.

Le handoff decrit l'etat actuel du depot ; chaque ADR indique son etat d'implementation. Le transport natif est differe et a evaluer, non abandonne. Les profils direct_proxy et integrated_proxy restent des configurations manuelles, pas un schema applicatif executable.
