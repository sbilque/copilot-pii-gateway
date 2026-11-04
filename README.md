# Copilot PII Gateway

Prototype experimental de pseudonymisation locale pour VS Code et GitHub Copilot, avec sortie par proxy d'entreprise. Reconstruction du prototype de la conversation : pas une importation identique de l'ancienne archive V3.

## Code et tests

- `pii_core.py` : detection, alias, propagation, cache, parcours JSON et restauration.
- `copilot_pii.py` : adaptateur mitmproxy.
- `test_core.py`, `test_addon.py` : 31 tests unitaires, dont hooks mitmproxy simules.
- `policy.json`, `config.yaml`, `px.ini.example` : exemples a adapter.
- `check_proxy.py` : canari synthetique local.

```bash
python -m unittest -v
```

Les tests utilisent la bibliotheque standard ; mitmproxy et Presidio ne sont pas requis pour les tests simules.

Installation et limites : [guide du prototype](docs/prototype.md).

## Statut et securite

Non valide contre Copilot reel, mitmproxy reel, Presidio ou un proxy NTLM/Kerberos. Le reverse proxy natif, wrap/unwrap et le schema reseau V4 ne sont pas implementes.

Difference importante avec le prototype historique : cette reconstruction bufferise integralement les reponses SSE avant restauration. Ce n'est pas un streaming interactif. Les plafonds de taille ne constituent pas une limite memoire avant reception.

Les secrets detectes sont bloques. Les alias inconnus ou malformes provoquent un refus de reponse. Cela ne garantit pas la detection de toutes les PII ni de tous les alias alteres. Aucune execution d'outils avec effets de bord pendant les essais.

## Documentation

- [Index](docs/README.md)
- [Handoff historique](docs/handoff.md) : photographie du premier commit documentaire ; pour l'etat actuel du code, lire ce README et le guide du prototype.
- [ADR architecture](docs/adr/001-architecture-and-transports.md)
- [ADR protection PII](docs/adr/002-fail-closed-pii-policy.md)
- [ADR proxy d'entreprise](docs/adr/004-enterprise-proxy-authentication.md)
- [Guide reseau](docs/network/proxy-enterprise.md)

Inspirations : [AgentRedactor](https://github.com/Negative-Star-Innovators/AgentRedactor), [Headroom](https://github.com/headroomlabs-ai/headroom), [Px](https://github.com/genotrance/px). Code reconstruit, sans copie de leurs composants. Licence MIT.
