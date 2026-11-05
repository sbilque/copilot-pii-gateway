# Supervision

Exemples pour lancer la passerelle et son canari periodique (`watch_proxy.py`, ADR-008) a l'ouverture de session. Non executes sur un poste reel : seuls la syntaxe (plistlib, `systemd-analyze verify`) et le comportement de `watch_proxy.py` (tests) sont verifies.

Comportement : toutes les 60 s, le canari interroge la passerelle. Apres 3 echecs consecutifs, il envoie SIGTERM a la passerelle et se termine. Aucun redemarrage automatique : une passerelle arretee reste fermee jusqu'a une intervention.

## macOS (launchd)

```bash
mkdir -p logs ~/Library/LaunchAgents
for f in gateway watch; do
  sed "s#REPO#$PWD#g" supervision/$f.plist > ~/Library/LaunchAgents/local.copilot-pii.$f.plist
  launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/local.copilot-pii.$f.plist
done
```

Arret : `launchctl bootout gui/$(id -u)/local.copilot-pii.watch` puis `.gateway`.

## Linux (systemd utilisateur)

Les unites supposent le depot dans `~/copilot-pii-gateway`.

```bash
mkdir -p ~/.config/systemd/user
cp supervision/*.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now copilot-pii-gateway copilot-pii-watch
```

## Verifier

`make canary` doit afficher `ready=true`. `CANARY_PROXY=http://127.0.0.1:1 .venv/bin/python watch_proxy.py --once` (port ferme) doit sortir avec le code 1. Avec un port non standard, definir `CANARY_PROXY` dans l'environnement du canari.
