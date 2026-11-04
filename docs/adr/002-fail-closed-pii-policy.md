# ADR-002 - Protection PII et echec ferme

- Date : 2026-11-04
- Statut : accepte pour la conception ; integration non validee.

## Decision

- Detection locale uniquement, par regles metier et detecteurs configurables.
- PII pseudonymisees avec table locale ; secrets bloques plutot que rehydrates.
- Une absence du filtre, une erreur ou un delai depasse interdit le transfert du corps sensible original.
- Ne jamais journaliser prompts, valeurs originales, credentials proxy ou jetons Copilot.
- Aucune execution d'outil ni approbation de securite contournee par la restauration.
- Restaurer uniquement les alias connus et exacts. Un alias inconnu ou altere dans un argument d'outil doit etre traite avant execution selon une politique explicite.
- Limiter taille, profondeur, concurrence, cache et duree de traitement.
- Isoler les mappings par contexte approprie ; ne pas partager un prototype mono-utilisateur entre utilisateurs.

## Limites

La detection a des faux positifs et negatifs. Le proxy ne couvre pas automatiquement les en-tetes, la telemetrie, les agents cloud, les requetes serveur ou les acces MCP directs. Les resultats MCP ne sont proteges que s'ils traversent effectivement le filtre avant envoi au modele. Une politique reseau reste necessaire pour empecher le contournement.

## Validation

Utiliser des donnees synthetiques ; verifier le corps sortant et la restauration, notamment des arguments JSON imbriques contenant guillemets et antislashs. Tester les alias decoupes, les appels paralleles et les erreurs.
