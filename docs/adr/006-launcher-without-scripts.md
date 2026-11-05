# ADR-006 - Lanceur sans chargement de scripts

- Date : 2026-11-05
- Statut : accepte ; implemente ; valide dans le lab et la CI, pas sur un poste reel.

## Contexte

Lance par `mitmdump` avec l'option `scripts`, l'addon est surveille par le chargeur de scripts de mitmproxy. Si le fichier change et ne se charge plus, mitmproxy decharge l'addon et continue a ecouter : le trafic Copilot passe alors sans filtre. Le lab l'a confirme (F3, transfert en clair). Une politique invalide au demarrage, elle, arrete deja mitmproxy.

## Decision

- `gateway.py` est le mode de lancement unique (`make run`, lab, CI). Il reprend les options et la ligne de commande de `mitmdump`, retire l'addon `scriptloader` du maitre et ajoute `CopilotPII` directement. Rien ne surveille plus les fichiers : aucun rechargement a chaud n'est possible.
- Demarrage refuse (code de sortie non nul) si `scripts` est present dans `config.yaml` ou passe par `-s`, ou si la politique est absente ou invalide. `check_config.py` refuse aussi `scripts`.
- La politique est lue une fois au demarrage. Pour en changer, redemarrer le processus : le mapping des alias est perdu, de facon explicite. Depuis le jalon 3, un alias d'une instance precedente est refuse (502).
- `mitmdump` reste un outil de diagnostic, pas un mode d'exploitation.

## Consequences

- Ferme : script ou module modifie ou casse pendant l'execution (F3), double chargement de l'addon, demarrage avec politique invalide (F4).
- Non ferme : processus arrete ou tue (le client n'a plus de proxy, ce qui est ferme), contournement du proxy par VS Code ou un autre processus (verrou reseau, jalon 7), supervision (jalon 6).
- Dependance a l'API interne `mitmproxy.tools.main.run` et au nom `scriptloader` : le lanceur refuse de demarrer si ce nom disparait. Versions bornees dans `requirements.txt`.

## Validation

- `test_gateway.py` : processus mitmproxy reels ; refus de `scripts` (configuration et `-s`), de politique invalide ou absente ; canari pret, puis toujours pret apres corruption de `copilot_pii.py` et `pii_core.py`.
- Lab : F3 passe ; `startup-check` verifie les refus de demarrage. Controle par mutation : `gateway-hot` relancee avec `mitmdump` et `scripts` fait echouer F3.
