# ADR-002 - Protection PII et echec ferme

- Date : 2026-11-04
- Statut : accepte ; partiellement implemente ; integration non validee.
- Mise a jour : 2026-11-05

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

## Etat d'implementation (2026-11-05)

| Decision | Etat |
|---|---|
| Detection locale | Implementee : regex, litteraux, IPv4 RFC1918, Presidio facultatif hors processus |
| Secrets bloques | Implemente via block_entities (SECRET obligatoire), y compris dans les noms d'outils exemptes |
| Erreur ou delai depasse -> pas de transfert | Implemente dans l'addon (403, 413, 503, 502) ; delai borne pour Presidio (ADR-005) |
| Absence du filtre -> pas de transfert | Non garanti : si l'addon echoue au chargement, mitmproxy peut continuer. Le canari le detecte sans le bloquer |
| Pas de journalisation des valeurs | Respecte par le code ; flow_detail 0 dans config.yaml ; le worker ne renvoie que des types |
| Restauration des seuls alias connus et exacts | Implemente en mode redact avec mapping non vide ; sinon les alias ne sont pas verifies |
| Limites | Taille, profondeur, alias, cache et delai du detecteur bornes ; taille verifiee apres reception, concurrence non bornee |
| Isolation des mappings | Non implementee : mapping global mono-utilisateur, sans TTL |

Validation realisee : donnees synthetiques uniquement, tests de guillemets, antislashs, retours ligne, toutes les positions de coupure d'un alias et appels paralleles. Validation restante : corps effectivement transmis vers un serveur amont de test.
