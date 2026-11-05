# Copilot PII Gateway

Prototype experimental de pseudonymisation locale pour VS Code et GitHub Copilot, avec sortie par proxy d'entreprise. Reconstruction du prototype de la conversation : pas une importation identique de l'ancienne archive V3.

## Code et tests

- `pii_config.py` : validation explicite de la politique avant initialisation.
- `pii_core.py` : detection, alias, propagation, cache, parcours JSON et restauration.
- `copilot_pii.py` : adaptateur mitmproxy (hooks async).
- `pii_detector.py`, `pii_worker.py` : Presidio dans un processus separe, avec delai borne, relance et refus en cas d'echec.
- `test_core.py`, `test_addon.py`, `test_regressions.py`, `test_worker.py` : 80 tests, dont hooks mitmproxy simules et processus worker reels pilotes par `fake_worker.py`.
- `policy.json`, `config.yaml`, `px.ini.example` : exemples a adapter.
- `check_proxy.py` : canari synthetique local.
- `check_config.py` : validation de config.yaml par le gestionnaire d'options mitmproxy.
- `Makefile` : preparation et verification de l'environnement de developpement.

```bash
make setup      # venv, mitmproxy, CA locale, tests et validations
make help       # liste des cibles
```

Sans make : `python -m unittest -v`.

Les tests utilisent la bibliotheque standard ; mitmproxy et Presidio ne sont pas requis. Un test supplementaire avec Presidio reel s'execute si `presidio_analyzer` et `en_core_web_sm` sont installes, sinon il est ignore.

Installation et limites : [guide du prototype](docs/prototype.md).

## Statut et securite

Non valide contre Copilot reel ou un proxy NTLM/Kerberos. Le worker Presidio a ete exerce avec Presidio reel (modele anglais) et un demarrage de mitmdump avec point de sante, sans trafic Copilot. Le reverse proxy natif, wrap/unwrap et le schema reseau V4 ne sont pas implementes.

Difference importante avec le prototype historique : cette reconstruction bufferise integralement les reponses SSE avant restauration. Ce n'est pas un streaming interactif. Les plafonds de taille ne constituent pas une limite memoire avant reception.

Les secrets detectes dans les corps analyses sont bloques, y compris dans les noms d'outils autrement exemptes. Lorsqu'une restauration est active (mode redact et mapping non vide), les alias inconnus ou malformes provoquent un refus de reponse. Cela ne garantit pas la detection de toutes les PII ni de tous les alias alteres. Aucune execution d'outils avec effets de bord pendant les essais.

Le client officiel conserve la gestion de l'authentification Copilot ; l'addon ne gere pas les jetons. L'interception HTTPS n'implique pas que les credentials soient invisibles au processus proxy. Les profils reseau restent des configurations manuelles, et le transport natif reste une piste a evaluer, pas une fonction publiee.

Le canari verifie un corps neutre, la protection d'un email synthetique et, en mode redact, sa restauration JSON. Il ne confond plus une erreur generique avec un blocage attendu. Il ne garantit ni le routage de Copilot ni un deploiement globalement fail-closed si l'addon est absent.

## Documentation

- [Index](docs/README.md)
- [Handoff historique](docs/handoff.md) : photographie du premier commit documentaire ; pour l'etat actuel du code, lire ce README et le guide du prototype.
- [ADR architecture](docs/adr/001-architecture-and-transports.md)
- [ADR protection PII](docs/adr/002-fail-closed-pii-policy.md)
- [ADR proxy d'entreprise](docs/adr/004-enterprise-proxy-authentication.md)
- [ADR worker Presidio](docs/adr/005-out-of-process-detector.md)
- [Guide reseau](docs/network/proxy-enterprise.md)

Inspirations : [AgentRedactor](https://github.com/Negative-Star-Innovators/AgentRedactor), [Headroom](https://github.com/headroomlabs-ai/headroom), [Px](https://github.com/genotrance/px). Code reconstruit, sans copie de leurs composants. Licence MIT.
