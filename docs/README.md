# Documentation

- [Handoff](handoff.md) : contexte, etat reel du depot, ecarts avec V3, risques et plan de reprise.
- [Guide du prototype](prototype.md) : installation avec make, configuration, politique et limites.
- [Plan](plan.md) : lab d'integration, filtre absent, isolation des alias ; jalons et decisions.
- [Lab d'integration](../lab/README.md) : banc Docker, commandes et scenarios.
- [ADR-001](adr/001-architecture-and-transports.md) : architecture et deux transports.
- [ADR-002](adr/002-fail-closed-pii-policy.md) : politique de securite PII.
- [ADR-004](adr/004-enterprise-proxy-authentication.md) : proxy sans authentification ou NTLM/Kerberos.
- [ADR-005](adr/005-out-of-process-detector.md) : Presidio hors processus, delai borne et echec ferme.
- [ADR-006](adr/006-launcher-without-scripts.md) : lanceur gateway.py sans chargement ni rechargement de scripts.
- [Guide reseau](network/proxy-enterprise.md) : exemples et validation.

La numerotation conserve ADR-004, nom utilise pendant la conception. Aucun ADR-003 n'est publie pour l'instant. Les ADR decrivent des decisions ; leur section Etat d'implementation indique ce qui est effectivement code et teste.
