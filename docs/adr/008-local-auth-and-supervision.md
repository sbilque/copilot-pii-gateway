# ADR-008 - Mot de passe du proxy local et supervision

- Date : 2026-11-06
- Statut : accepte ; implemente ; valide par tests unitaires et lab. Non verifie avec VS Code ni sur launchd ou systemd reels.

## Contexte

Le port local de la passerelle est joignable par tout utilisateur de la machine. Sans authentification, un autre utilisateur local peut faire restaurer des alias de la portee du proprietaire (ADR-007). Par ailleurs, le canari etait manuel : rien ne reagissait a un filtre devenu inoperant.

## Decision

- Mot de passe optionnel, desactive par defaut. `make proxy-secret` cree `proxy-auth` (une ligne `copilot:<secret>`, mode 600, non versionne). Si ce fichier existe (`COPILOT_PII_PROXY_AUTH`), `gateway.py` l'applique dans le processus via l'option `proxyauth` de mitmproxy. Le secret n'apparait jamais en ligne de commande.
- Demarrage refuse si le fichier n'est pas un fichier regulier, s'il est lisible par le groupe ou les autres, s'il appartient a un autre utilisateur, ou si le mot de passe a moins de 16 caracteres. L'option `proxyauth` passee par `config.yaml`, `--set` ou `--proxyauth` est refusee : une seule source.
- Un client sans identifiants valides recoit 407 avant toute analyse, canari compris. `check_proxy.py` et `watch_proxy.py` lisent le meme fichier.
- Supervision : `watch_proxy.py` interroge le canari (60 s par defaut). Apres 3 echecs consecutifs, il alerte sur la sortie d'erreur et envoie SIGTERM a la passerelle (pid ecrit par `COPILOT_PII_PIDFILE`), puis se termine. Une passerelle arretee est fermee ; pas de redemarrage automatique. Exemples launchd et systemd dans `supervision/`.

## Consequences

- Avec le secret, la portee par utilisateur (ADR-007) est protegee contre les autres utilisateurs locaux, sauf root ou administrateur.
- VS Code doit envoyer les identifiants. La documentation VS Code indique la prise en charge de Basic par une invite, et celle de GitHub Copilot les identifiants dans l'URL du proxy. Ce depot ne l'a pas verifie : l'option reste desactivee par defaut. Un secret dans `settings.json` est en clair et peut etre synchronise.
- Basic sur la boucle locale : le secret circule en clair sur loopback, lisible seulement par root ou par capture locale privilegiee.

## Validation

- `test_gateway.py`, processus mitmproxy reels : 407 sans identifiants ou avec de mauvais identifiants (canari et CONNECT), canari pret avec le secret, secret absent de la ligne de commande, refus des fichiers lisibles, liens symboliques, secrets faibles et options `proxyauth` concurrentes ; superviseur qui arrete une passerelle dont le canari echoue et laisse en place une passerelle prete.
- Lab : `gateway-auth` refuse un client sans secret (407) et filtre normalement avec le secret.
