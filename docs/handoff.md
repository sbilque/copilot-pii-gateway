# Handoff pour un autre LLM ou developpeur

Date : 2026-11-05, etat du code au commit 5979695. Ce document distingue les decisions de conception, le prototype historique V3 et le contenu effectivement publie et teste dans ce depot. La premiere version (2026-11-04, commit 964b06c) decrivait un depot sans code ; elle reste consultable dans l'historique Git.

## Mission

Construire une passerelle PII locale pour VS Code et GitHub Copilot en conservant l'abonnement fourni par l'entreprise. Les vraies valeurs restent visibles localement ; seuls des alias sont envoyes au modele ; les reponses sont restaurees avant affichage ou utilisation locale. Cas envisage : AWX via MCP, avec noms d'hotes, IP privees et identifiants metier.

Toute sortie Internet passe par un proxy d'entreprise, sans authentification ou avec NTLM/Kerberos via Px. Pas de cle API fournisseur externe imposee. Les secrets doivent etre bloques plutot que rendus reversibles. Ne pas contourner les approbations d'outils.

## Etat reel du depot

| Commit | Contenu |
|---|---|
| 964b06c | Documentation, ADR-001, 002, 004, guide reseau, premiere passation |
| 9119ab9 | Reconstruction du prototype : coeur, addon mitmproxy, 31 tests |
| 1f2f64e | Validation de la politique, secrets dans les noms d'outils, arguments SSE Responses, canari renforce (58 tests) |
| f2ef1eb | Presidio dans un worker a delai borne, ADR-005 (80 tests) |
| 5979695 | Makefile, check_config.py, requirements-px.txt |
| 4843ce4 | Mise a jour des ADR et de ce handoff |
| jalon 1 | Lab Docker (mitmproxy, Squid, faux Copilot), devcontainer, CI GitHub Actions, plan |
| jalon 2 | Lab : SSE, pannes F1 a F7, canari depuis le reseau client |
| jalon 3 | Verification des alias en mode redact meme avec un mapping vide |
| jalon 4 | Lanceur gateway.py sans scripts ni rechargement (ADR-006), F3 corrige |

Le code est une reconstruction des principes de V3, pas une importation de l'archive V3, qui n'est pas dans le depot. Les 51 tests historiques ne sont pas reproductibles ; ils sont remplaces par 85 tests reproductibles.

Fichiers : gateway.py (lanceur), pii_config.py (validation), pii_core.py (detection, alias, parcours, restauration), pii_detector.py et pii_worker.py (Presidio hors processus), copilot_pii.py (addon), check_config.py et check_proxy.py (verifications), test_*.py et fake_worker.py (tests), policy.json, config.yaml, px.ini.example, requirements*.txt, Makefile.

Valide : 91 tests unitaires, dont 22 avec processus worker reels, 6 avec mitmproxy reel (lanceur) et 1 avec Presidio reel (en_core_web_sm) ; `make setup` depuis un venv vide (Python 3.14, mitmproxy 12.3.1) ; demarrage de la passerelle et canari ready ; demarrage de Px 0.13 sur 127.0.0.1:3128. Lab d'integration : 21 tests avec mitmproxy reel, Squid et faux serveur Copilot en HTTPS verifie (N1 a N7, F1 a F7, C1, isolation reseau) et la verification de demarrage F4 (politique invalide, scripts), executes aussi dans la CI. Non valide : trafic Copilot reel, proxy d'entreprise reel, NTLM/Kerberos (methode manuelle documentee, non bloquante), modeles francais, charge.

## Demarrage rapide

```bash
make setup        # venv, mitmproxy, CA locale, tests, politique, config.yaml
make doctor       # etat et etapes manuelles
make run          # proxy au premier plan
make canary       # depuis un autre terminal
make lab          # lab d'integration Docker complet
```

Le devcontainer (`.devcontainer/`) fournit Python 3.12, make et Docker ; `make setup` y est lance a la creation.

Etapes manuelles : proxy amont dans config.yaml, installation de la CA publique avec accord securite, proxy VS Code. Voir le [guide du prototype](prototype.md).

## Comportement implemente

- Politique JSON chargee avec rejet des cles dupliquees et constantes non standard, puis validee (ConfigurationError) avant tout detecteur.
- Modes block (defaut) et redact. Pas de mode audit.
- Detection : regex de la politique, litteraux, IPv4 RFC1918, Presidio facultatif via worker. Pas de plugins module:fonction.
- Alias __PII_<12 hex>_<6 chiffres>__, stables pendant la vie du mapping, propagation des valeurs connues (3 caracteres minimum, frontieres de mots), cache LRU par empreinte BLAKE2b.
- Parcours JSON : schema racine reconnu exige (messages, prompt, input, system, instructions, suffix) ; detection dans un champ structurel ou un nom de cle -> blocage ; `tools` analyse sans reecriture ; noms d'outils preserves sauf categorie bloquee ; blocs signes, thinking, multimedia et gros data: refuses.
- Addon : hotes Copilot seulement ; HTTPS, JSON, sans query ni upgrade ; 413 sur longueur declaree excessive ; 403 sur refus de politique ; 503 si le detecteur est indisponible ; Accept-Encoding: identity ; octets originaux conserves si rien ne change.
- Restauration en mode redact, meme avec un mapping vide : JSON recursif et SSE entierement bufferise ; arguments, partial_json et deltas Responses parses avant restauration ; alias inconnu ou malforme -> 502.
- Canari pii-gate.invalid : loopback sans Origin ; corps neutre, email synthetique bloque ou pseudonymise puis restaure, etat du detecteur.

## Ecarts avec V3

| V3 | Reconstruction |
|---|---|
| Mode audit | Absent volontairement |
| tools_policy, unknown_roots, data_uri_policy | Comportements fixes : tools analyse, racine inconnue refusee, gros data: refuses |
| Plugins de detection | Absents |
| SSE incremental avec retention des suffixes d'alias | Remplace par une bufferisation complete |
| Presidio synchrone | Worker separe a delai borne |
| run.sh, run.ps1, vscode-settings.json, detector_example.py | Remplaces par le Makefile et le guide |

## Risques techniques

| Risque | Etat |
|---|---|
| Arguments JSON imbriques avec guillemets, antislashs, controles | Traite et teste, y compris deltas Responses et appels paralleles |
| Secret dans un nom d'outil exempte | Traite : refuse dans les deux modes |
| Canari confondant erreur et blocage attendu | Traite |
| Detection lente bloquant la boucle | Traite par ADR-005 |
| Plafond verifie apres buffering, pas de limite memoire globale ni de concurrence | Ouvert |
| Mapping global mono-utilisateur, sans TTL ni isolation | Ouvert |
| Alias non verifies avec un mapping vide | Traite (jalon 3) ; le mode block ne verifie pas les reponses |
| Couverture protocolaire et chemins JSON entre evenements SSE | Partiel, a tester sur captures representatives |
| Absence du filtre si l'addon echoue au chargement | Traite dans le processus (jalon 4, ADR-006) : gateway.py refuse de demarrer sans politique valide ou avec scripts, et ne recharge rien ; contournement du proxy ouvert (jalon 7) |
| Health ne prouve pas le routage de la fenetre VS Code | Ouvert |
| Reprise apres redemarrage, historique fournisseur opaque | Non garanti |
| En-tetes, telemetrie, agents cloud, contexte serveur, MCP direct | Non couverts |

## Inspiration AgentRedactor

Depot : Negative-Star-Innovators/AgentRedactor. Revision observee : 0696a735d3da98f34f40496c26ed2e817da50326. Lecture de proxy_engine.h, proxy_engine.cpp tronque, redactor.cpp, api_key_profile.h, http_server.h et pii_detector.h. Pas d'audit complet.

Idees reprises et implementees : propagation, cache, cles structurelles, exemptions contextuelles et separation des canaux. Ecarts volontaires : secrets bloques, outils analyses et gros data: bloques. Ne pas affirmer son support du proxy d'entreprise sans lecture supplementaire. Aucun code copie.

## Inspiration Headroom

Depot : headroomlabs-ai/headroom. Fichiers lus : providers/copilot/vscode.py et wrap.py ; proxy/body_forwarding.py, request_body_limit.py, extensions.py, loopback_guard.py, hard_watchdog.py, auth_mode.py, forwarded_headers.py ; docs/content/docs/vscode-copilot.mdx.

Redirection VS Code observee : github.copilot.advanced.debug.overrideProxyUrl et overrideCapiUrl vers une URL locale, parametres de debug dependants de version, non valides ici. Le CLI utilise COPILOT_API_URL. Un reverse proxy peut potentiellement conserver l'abonnement ; routage et authentification restent a auditer.

Repris dans la reconstruction : octets originaux si non modifies, garde loopback/Origin du canari, refus plutot que repli sur le corps original. Restent a reprendre : wrap/unwrap JSONC, profils VS Code, limite avant buffering, supervision. A ne pas recopier : demarrage sans extension PII si elle echoue, abandon d'une mutation au profit du corps original, heuristique d'authentification comme frontiere de securite.

## Reseau

Voir ADR-004 et le guide reseau. Les profils direct_proxy et integrated_proxy sont realises manuellement : mode upstream de config.yaml, et pour NTLM/Kerberos `make px-config` puis `make px` avec `upstream:http://127.0.0.1:3128`. Il n'existe pas de gestionnaire de profils ni de schema network V4 executable. Aucun repli direct n'est configure, mais aucun verrou reseau ne l'empeche.

## Plan de reprise

Plan detaille et decisions : [plan.md](plan.md).


| Etape | Etat |
|---|---|
| Reconstruire le prototype et rendre les tests reproductibles | Fait (91 tests) |
| Isoler les detecteurs et borner leur delai | Fait pour Presidio (ADR-005) |
| Preserver les octets si rien ne change ; bloquer si la protection est impossible | Fait |
| Auditer restauration JSON imbriquee et SSE | Fait pour les cas testes ; blocs signes refuses |
| Outillage de developpement reproductible | Fait (Makefile) |
| Integration avec vrai mitmproxy, serveur amont de test et proxy de test | Fait : N1 a N7, F1 a F7, C1 (lab J1 a J4) |
| Limiter memoire avant buffering et concurrence ; isolation et duree de vie des mappings | A faire |
| Decider du streaming SSE incremental | A decider |
| Verrou reseau et supervision de l'absence du filtre | A faire |
| Separer core, protocol, transports, upstream, CLI ; profils reseau executables | A faire |
| NTLM/Kerberos reel | Pas de test automatise ; methode manuelle dans le guide reseau |
| Transport natif experimental, wrap/unwrap, doctor VS Code | Differe |
| Validation sur poste autorise avec donnees synthetiques, pannes et identites | A faire |

## Consignes au repreneur

Ne pas confondre decisions, implementation historique et contenu present. Lancer `make check` avant toute modification et ajouter un test pour chaque correction. Ne pas annoncer un code teste sans resultat reproductible. Ne pas publier de secrets, de donnees personnelles ni la cle privee de la CA. Ne pas qualifier de production-ready. Conserver les approbations d'outils et eviter les actions AWX avec effets de bord lors des tests.
