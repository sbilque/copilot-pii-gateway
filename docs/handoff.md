# Handoff pour un autre LLM ou developpeur

Date : 2026-11-04. Ce document reprend les decisions d'une conversation de conception. Il distingue les prototypes historiques du contenu effectivement publie.

## Mission

Construire une passerelle PII locale pour VS Code et GitHub Copilot en conservant l'abonnement fourni par l'entreprise. Les vraies valeurs restent visibles localement ; seuls des alias sont envoyes au modele ; les reponses sont restaurees avant affichage ou utilisation locale. Cas envisage : AWX via MCP, avec noms d'hotes, IP privees et identifiants metier.

Toute sortie Internet passe par un proxy d'entreprise, sans authentification ou avec NTLM/Kerberos via Px. Pas de cle API fournisseur externe imposee. Les secrets doivent etre bloques plutot que rendus reversibles. Ne pas contourner les approbations d'outils.

## Etat reel du depot

Ce commit contient documentation et ADR uniquement. Aucun code executable du prototype n'a encore ete importe. Des archives ont ete generees pendant la conversation mais elles ne sont pas automatiquement disponibles dans une nouvelle session. Recuperer l'archive V3 ou reconstruire explicitement le prototype ; ne pas pretendre qu'une reimplementation est identique.

Le prototype V3 a fait l'objet de 51 tests unitaires et de flux simules annonces reussis. Ces tests ne sont pas encore dans le depot et ne sont donc pas reproductibles ici. Aucun test reel avec Copilot, mitmproxy installe, Presidio, Px ou le proxy d'entreprise n'a ete effectue.

## Architecture

Transport historique : client Copilot officiel -> mitmproxy local avec interception HTTPS -> proxy d'entreprise -> GitHub Copilot. Certificat local approuve necessaire.

Cible : moteur PII commun, adaptateur mitmproxy conserve et reverse proxy natif Copilot experimental. Ne pas supprimer mitmproxy avant validation du routage natif et de son authentification.

## Prototype V3 a recuperer

Fichiers historiques : copilot_pii.py, policy.json, test_guard.py, test_addon.py, check_proxy.py, config.yaml, vscode-settings.json, run.sh, run.ps1, px.ini.example, detector_example.py, requirements.txt, requirements-presidio.txt, README.md, LICENSE.

Classes principales : Guard, StreamRestorer, CopilotPII.

Modes : block (defaut), redact, audit (envoi en clair, donnees synthetiques seulement). Detection : emails, IPv4 RFC1918, domaines corp/internal/lan, certains tokens GitHub, cles privees et valeurs litterales ; Presidio fr/en facultatif ; plugins module:fonction retournant (debut, fin exclusive, type).

Alias : __PII_<12 caracteres hex aleatoires>_<compteur sur 6 chiffres>__. Mapping en memoire, capacite bornee, propagation des valeurs deja masquees avec frontieres de mots et longueur minimale 3. Cache LRU des detecteurs lourds, indexe par BLAKE2b 16 octets, sans texte, 2000 entrees par defaut. Regex et propagation recalculees.

Parcours JSON : champs structurels id, tool_call_id, tool_use_id, call_id, previous_response_id, model, role, type, stop, stop_sequences. Detection dans ces champs -> blocage. Exemptions contextuelles de name pour les identifiants d'outils ; autres name analyses.

Options : tools_policy=block|inert ; unknown_roots=redact|block ; data_uri_policy=block|skip. tools_policy=block analyse sans reecrire les declarations ; inert les ignore. data_uri_policy=skip peut laisser passer des donnees encodees sensibles. Schema racine reconnu exige : messages, prompt, input, instructions, system ou suffix.

Restauration : JSON recursif et SSE avec retention des suffixes d'alias. Canaux par type, item_id, output_index, content_index, index et chemin JSON. Tests simules Chat Completions, Responses, style Anthropic, arguments d'outils et fragmentation reseau. Cela ne garantit pas une couverture exhaustive des protocoles.

## Risques techniques a traiter

- Alias inconnu ou altere : ne pas executer aveuglement un outil avec une valeur ambigue.
- Auditer les arguments JSON imbriques lorsque les valeurs restaurees contiennent guillemets, antislashs ou controles.
- Auditer les canaux paralleles, identifiants et evenements terminaux SSE.
- Le plafond historique de 4 Mio etait verifie apres buffering, pas avant allocation.
- Les reponses compressees etaient refusees lorsque la restauration etait requise ; Accept-Encoding: identity force en requete.
- Politique des blocs signes/opaques non resolue.
- Mapping global mono-utilisateur : isolation de contexte et concurrence a definir.
- Health ne prouve pas le routage de la fenetre VS Code.
- Le comportement exact de reprise apres redemarrage depend de l'historique local et des etats opaques du fournisseur ; ne pas garantir la reprise sans tests.
- En-tetes, telemetrie, agents cloud, contexte serveur et acces MCP directs ne sont pas automatiquement couverts.

## Inspiration AgentRedactor

Depot : Negative-Star-Innovators/AgentRedactor. Revision observee : 0696a735d3da98f34f40496c26ed2e817da50326. Lecture de proxy_engine.h, proxy_engine.cpp tronque, redactor.cpp, api_key_profile.h, http_server.h et pii_detector.h. Pas d'audit complet.

Observations : reverse proxy par profil avec upstreamUrl/apiKey/port, NER ONNX/BPE/Viterbi, propagation, cache, parcours JSON avec exemptions, compteurs persistes sans PII et reconstruction SSE. Idees reprises : propagation, cache, cles structurelles, exemptions et separation des canaux. Ecarts volontaires : secrets bloques, outils analyses et gros data: bloques par defaut. Ne pas affirmer son support du proxy d'entreprise sans lecture supplementaire.

## Inspiration Headroom

Depot correct : headroomlabs-ai/headroom. Fichiers lus : providers/copilot/vscode.py et wrap.py ; proxy/body_forwarding.py, request_body_limit.py, extensions.py, loopback_guard.py, hard_watchdog.py, auth_mode.py, forwarded_headers.py ; docs/content/docs/vscode-copilot.mdx.

Redirection VS Code observee : github.copilot.advanced.debug.overrideProxyUrl et github.copilot.advanced.debug.overrideCapiUrl vers une URL locale. Parametres internes/de debug dependants de version, non valides dans notre environnement. Le CLI utilise un mecanisme distinct : COPILOT_API_URL avec suppression des COPILOT_PROVIDER_* pour ne pas rester en BYOK.

Correction de conception : un reverse proxy peut potentiellement conserver l'abonnement Copilot ; l'affirmation initiale du contraire etait trop categorique. Il faut auditer le routage et l'authentification. Headroom utilise un device flow, des jetons courts, des politiques distinctes inline/Chat et l'endpoint annonce par GitHub. Ne pas supposer une transmission automatique des credentials.

A reprendre : wrap/unwrap JSONC avec bloc gere, profils VS Code, redirection conservee a l'arret, octets originaux si non modifies, mutations explicites, protection des blocs signes, limite avant buffering, garde Host/Origin et supervision.

A ne pas recopier : demarrage sans extension PII si elle echoue ; abandon d'une mutation PII au profit du corps original ; heuristique d'authentification utilisee comme frontiere de securite.

## Reseau

Voir ADR-004 et le guide reseau. Deux profils : direct_proxy vers le proxy d'entreprise sans authentification et integrated_proxy vers Px local. Aucun repli Internet direct. SSPI prefere sous Windows lorsque possible ; identite en service et tickets Kerberos a valider ailleurs. Pas de mot de passe dans Git. Les echanges et renouvellements de jetons geres par la passerelle suivent la meme politique reseau.

Le schema network dans la documentation est une proposition V4, pas du code implemente.

## Plan de reprise

1. Recuperer/reconstruire V3 et rendre les tests reproductibles.
2. Separer core, protocol, transports, upstream et CLI.
3. Implementer les profils reseau sans fallback direct.
4. Limiter les corps avant buffering, isoler les detecteurs et borner les delais.
5. Preserver les octets si rien ne change ; bloquer si la protection necessaire ne peut pas etre appliquee.
6. Auditer restauration JSON imbrique, SSE et blocs signes.
7. Ajouter integration avec vrai mitmproxy et proxy de test.
8. Ajouter transport natif experimental et wrap/unwrap/doctor.
9. Valider sur poste autorise avec donnees synthetiques, y compris pannes et identites.

## Consignes au repreneur

Ne pas confondre decisions, implementations historiques et contenu present. Ne pas annoncer un code teste sans executable et resultat reproductible. Ne pas publier de secrets ou donnees personnelles. Ne pas qualifier de production-ready. Conserver les approbations d'outils et eviter les actions AWX avec effets de bord lors des tests.
