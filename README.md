# Copilot PII Gateway

Passerelle locale de pseudonymisation des donnees sensibles pour VS Code et GitHub Copilot, avec conservation de l'abonnement Copilot et sortie par proxy d'entreprise.

## Statut

Prototype experimental en cours de consolidation. Ce premier commit publie la documentation et les decisions de conception, pas le code executable. Les archives de prototype produites pendant la conception ne sont pas encore importees dans ce depot.

Des tests unitaires et des flux simules ont ete executes dans les prototypes precedents. Ils ne prouvent pas une integration reelle avec Copilot, mitmproxy, Presidio ou un proxy NTLM/Kerberos. Leurs resultats ne sont pas reproductibles depuis ce commit documentaire.

## Architecture cible

```text
VS Code / GitHub Copilot
  -> transport mitmproxy OU passerelle native experimentale
  -> detection locale et pseudonymisation
  -> proxy d'entreprise, directement ou via Px
  -> GitHub Copilot
  -> restauration locale des alias dans les reponses
```

Les secrets sont bloques plutot que rendus reversibles. Une panne du filtre ne doit jamais provoquer l'envoi du corps original sensible.

## Documentation

- [Index](docs/README.md)
- [Handoff pour un autre LLM ou developpeur](docs/handoff.md)
- [Architecture et transports](docs/adr/001-architecture-and-transports.md)
- [Politique de confidentialite](docs/adr/002-fail-closed-pii-policy.md)
- [Sortie par proxy d'entreprise](docs/adr/004-enterprise-proxy-authentication.md)
- [Configuration reseau](docs/network/proxy-enterprise.md)

## Prochaines etapes

1. Recuperer ou reconstruire le code du prototype et rendre les tests reproductibles.
2. Separer moteur PII, protocoles, transports et configuration reseau.
3. Ajouter des tests d'integration avec un vrai mitmproxy et un proxy amont de test.
4. Evaluer la redirection native Copilot sans interception TLS.
5. Valider chaque profil sur un poste autorise, avec des donnees synthetiques.

## Inspirations

- AgentRedactor : https://github.com/Negative-Star-Innovators/AgentRedactor
- Headroom : https://github.com/headroomlabs-ai/headroom
- Px : https://github.com/genotrance/px

Les choix de ces projets sont des inspirations, pas une preuve de compatibilite du present projet. Aucun de leurs composants n'est embarque par ce commit.
