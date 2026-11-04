# ADR-001 - Architecture et transports

- Date : 2026-11-04
- Statut : accepte pour la conception ; integration non validee.

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
