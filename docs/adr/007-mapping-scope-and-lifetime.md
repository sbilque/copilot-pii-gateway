# ADR-007 - Portee et duree de vie du mapping des alias

- Date : 2026-11-05
- Statut : accepte ; implemente ; valide par tests unitaires et lab, pas sur un poste reel.

## Contexte

Le mapping alias -> valeur reelle est la donnee la plus sensible de la passerelle : il contient les valeurs que le filtre retire des requetes. Avant ce jalon, il vivait dans l'objet `Guard` sans borne de duree et etait partage par tout client qui joignait le port local.

## Decision

- Le mapping est porte par `MappingStore` (`pii_mapping.py`), en memoire seulement, jamais ecrit sur disque ni journalise. Le canari ne publie que des compteurs (`scope`, `aliases`, `ttl_s`, `purges`).
- Portee : une passerelle par utilisateur du systeme, sur son propre port local (`make run GATEWAY_PORT=...`). La portee est etiquetee `uid-<uid>` (ou `mapping_scope` dans la politique).
- Duree de vie : purge apres `mapping_ttl_s` secondes sans emission ni restauration d'alias (defaut 28800, soit 8 heures ; de 1 a 604800). Purge aussi a l'arret du processus.
- Un alias n'est jamais reattribue : compteur croissant conserve apres purge, prefixe aleatoire par instance et renouvele si le compteur atteint 999999. Un alias expire ou d'une autre instance est refuse (502, jalon 3).
- Capacite : `max_aliases` borne les alias vivants d'une portee.

## Consequences

- Une conversation reprise apres 8 heures d'inactivite ou apres un redemarrage ne peut plus restaurer ses anciens alias : refus explicite, jamais d'alias brut.
- L'isolation entre utilisateurs repose sur des ports distincts. Un autre utilisateur local peut encore joindre le port : le mot de passe optionnel du proxy local (jalon 6) le ferme.
- Pas de portee par conversation : Copilot n'expose pas d'identifiant de conversation stable dans les requetes.

## Validation

- `test_mapping.py` : horloge simulee ; purge par inactivite, prolongation par activite, non-reutilisation, rotation du prefixe, capacite, copies isolees, validation de `mapping_ttl_s` et `mapping_scope`.
- `test_addon.py` : purge a l'arret, portee par uid, canari sans valeur. `test_gateway.py` : `--listen-port` prime sur `config.yaml`.
- Lab : `gateway-ttl` (3 s) refuse un alias expire et n'emet jamais de nouveau le meme alias.
