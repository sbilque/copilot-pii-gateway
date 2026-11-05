# ADR-001 - Architecture et transports

- Date : 2026-11-04
- Statut : accepte ; transport mitmproxy implemente, transport natif differe ; integration Copilot non validee.
- Mise a jour : 2026-11-05

## Contexte

Proteger les donnees envoyees a GitHub Copilot dans VS Code sans remplacer l'abonnement par une cle API externe. La sortie Internet doit emprunter le proxy d'entreprise.

## Decision

Separer le moteur PII des protocoles et des transports. Conserver un adaptateur mitmproxy et evaluer un reverse proxy natif Copilot. Les deux utilisent la meme politique de detection, de pseudonymisation et de restauration.

Le transport mitmproxy conserve le client officiel et necessite un certificat local d'interception approuve. Le transport natif est inspire de Headroom et utilise des redirections d'endpoints Copilot dependantes de la version. Son authentification doit etre auditee separement ; ne pas supposer qu'elle se transmet automatiquement.

## Consequences

- Maintenir mitmproxy comme reference tant que le routage natif n'est pas valide.
- Pas de fournisseur BYOK impose a l'utilisateur.
- Adapter explicitement Chat Completions, Responses, les completions et les flux SSE.
- Conserver les octets originaux uniquement lorsqu'aucune modification de protection n'est requise.
- Les blocs signes ou opaques necessitent une politique explicite : aucune modification aveugle ni abandon silencieux du filtrage.

## Validation

Tester chaque chemin, l'identite Copilot, les changements de modele, les profils VS Code et les environnements distants. Une reponse de health ne prouve pas que les requetes de la fenetre active traversent le filtre.

## Etat d'implementation (2026-11-05)

- Moteur PII separe de l'adaptateur : pii_core.py, pii_config.py, pii_detector.py ; copilot_pii.py ne contient que le transport mitmproxy. Les adaptateurs de protocole ne sont pas encore des modules distincts.
- Transport mitmproxy : implemente, demarre et teste par hooks simules et canari ; pas de serveur amont de test ni de trafic Copilot.
- Transport natif : non implemente. Differe, pas abandonne ; a reevaluer apres l'integration mitmproxy reelle.
- Octets originaux conserves si rien ne change : implemente.
- Blocs signes, thinking et multimedia : refuses. C'est la politique explicite retenue pour l'instant, en attendant une analyse par type de bloc.
- Chat Completions, Responses et style Anthropic couverts par des tests de restauration ; completions et autres schemas non garantis.
