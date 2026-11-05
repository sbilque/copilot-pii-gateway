# ADR-005 - Detection lente hors processus, delai borne et echec ferme

- Date : 2026-11-05
- Statut : implemente ; teste avec un faux worker et avec Presidio reel (en_core_web_sm) hors Copilot.

## Contexte

Presidio etait appele de facon synchrone dans Guard.spans(), dans le processus mitmproxy. Une analyse lente bloquait la boucle asyncio, donc tous les flux et le point de sante, sans aucun delai. Un delai sur un thread ne suffit pas : le thread ne peut pas etre interrompu et continue a consommer CPU et memoire.

## Decision

- Presidio s'execute dans un sous-processus dedie et persistant, pii_worker.py, lance par pii_detector.PresidioWorker avec subprocess (meme mecanisme sous Linux, macOS et Windows ; pas de fork d'un processus asyncio multithread).
- Protocole : une ligne JSON ASCII par message sur stdin/stdout ; aucune valeur ni message d'exception ne sort du worker, seulement des noms de types. stdout de bibliotheque redirige vers stderr ; stderr du worker jete par defaut.
- Le coeur reste synchrone. Guard.collect() parcourt le corps sur une copie avec le meme walk() que request(), et retourne les textes a analyser et les resultats deja en cache (copies, pour resister a une eviction concurrente). Guard.request(body, prefetched) applique les resultats sans attente.
- Le hook mitmproxy request est async : collect, puis await analyze_many, puis request. La seule attente est l'analyse ; les mutations du mapping restent atomiques sans verrou.
- Un budget unique par requete HTTP (presidio_timeout_ms) couvre l'attente dans la file et l'analyse. Depassement, plantage, reponse corrompue ou fermeture du canal : le processus est tue, relance, et la requete refusee en 503.
- Un seul lot en cours ; file bornee (presidio_queue), refus 503 immediat si elle est pleine. Texte plus long que presidio_max_chars : refus 403 avant envoi.
- Pendant le demarrage ou une relance, refus 503 immediat, sans attente du chargement du modele.
- Disjoncteur : au-dela de presidio_max_restarts relances dans presidio_restart_window_s secondes, etat failed et refus systematique jusqu'au rechargement de la politique ou au redemarrage de mitmproxy.
- Le point de sante pii-gate.invalid expose detector (disabled, starting, ready, failed, stopped) et ne repond ready=true que si le worker est pret et que le canari passe par lui.
- Un rechargement de politique pendant une analyse refuse la requete en cours (503). Le hook done() arrete le worker.
- Aucun resultat en echec n'est mis en cache. Un texte sans resultat au moment de request() leve PolicyError : jamais d'envoi sans analyse.

## Options ecartees

- Thread avec asyncio.wait_for : delai non reellement borne.
- multiprocessing : re-importe le module principal de mitmdump en mode spawn et utilise pickle ; subprocess avec JSON est plus explicite.
- Service HTTP Presidio (Docker ou app.py) : surface reseau locale et dependance supplementaires. Peut etre ajoute plus tard derriere la meme interface analyze_many.
- Pool de plusieurs workers : memoire spaCy multipliee ; a reevaluer apres mesures.

## Consequences et limites

- Le delai borne la reponse et le calcul : le processus en depassement est tue. Il ne borne pas le temps de chargement initial du modele, pendant lequel les requetes sont refusees.
- Une relance recharge le modele spaCy : plusieurs secondes de refus apres chaque depassement.
- Le worker suppose que mitmproxy tourne dans un interpreteur Python capable de lancer pii_worker.py (installation pip dans un venv). Avec un binaire mitmproxy autonome, renseigner presidio_python vers un Python disposant de presidio-analyzer et du modele.
- Les valeurs par defaut (3000 ms, 200000 caracteres, file de 8, 3 relances en 60 s) sont des points de depart, non mesures sur un poste cible.
- Valide : 22 tests avec processus enfants reels (faux analyseur), un test avec Presidio reel et en_core_web_sm, un demarrage de mitmdump 12.3 avec point de sante ready et arret sans processus orphelin. Non valide : Copilot reel, proxy d'entreprise, modeles francais, charge reelle.

## Outillage (2026-11-05)

`make setup-presidio` installe requirements-presidio.txt et le modele choisi (`PRESIDIO_MODEL`, fr_core_news_lg par defaut) dans le venv utilise par mitmdump, ce qui satisfait l'hypothese d'interpreteur ci-dessus sans presidio_python. Avec en_core_web_sm installe, aucun test Presidio n'est ignore. Le modele francais n'a pas ete exerce.
