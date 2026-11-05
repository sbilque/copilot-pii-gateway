# ADR-009 - Verrou reseau contre le contournement de la passerelle

- Date : 2026-11-06
- Statut : accepte ; exemples fournis ; Linux (nftables) verifie dans le lab ; macOS et Windows non verifies.

## Contexte

Le lanceur (ADR-006) et le canari (ADR-008) garantissent qu'une passerelle en marche filtre. Ils n'empechent pas VS Code, ou un autre processus, de joindre directement le proxy d'entreprise sans passer par la passerelle (reglage `http.proxy` modifie, variable d'environnement, outil tiers).

## Decision

- La passerelle tourne sous un utilisateur systeme dedie (exemple : `copilot-gw`), distinct de l'utilisateur de VS Code.
- Une regle du poste n'autorise que cet utilisateur a ouvrir une connexion TCP vers le proxy d'entreprise ; les autres recoivent un refus immediat (RST), pas un delai.
- Exemples dans `network-lock/` : `linux.nft` (nftables, `meta skuid`), `macos.pf` (pf, mot-cle `user`), `windows.ps1` (pare-feu Windows). Le depot n'applique aucune regle automatiquement : elles relevent de l'administration du poste et de la securite.
- Hypothese : le poste n'a pas de route directe vers Internet hors du proxy d'entreprise (cas habituel). Sinon, etendre la regle aux ports 80/443 de toutes les destinations non locales.

## Consequences

- La portee des alias (ADR-007) devient l'uid de l'utilisateur dedie. Pour plusieurs utilisateurs humains, prevoir un utilisateur dedie et un port par personne, et le mot de passe local (ADR-008).
- Le secret `proxy-auth`, la CA et le pid appartiennent a l'utilisateur dedie ; VS Code ne recoit que le certificat public de la CA.
- Windows : le pare-feu fait primer les regles de blocage, d'ou un blocage de VS Code (par programme) plutot qu'une liste d'autorisation. C'est plus faible : un autre programme n'est pas couvert.
- root ou un administrateur peuvent retirer la regle : c'est une defense en profondeur, pas une isolation contre l'administrateur.

## Validation

- `lab/test_lock.py` (service `lock`, `make lab`) charge `network-lock/linux.nft` avec nftables reel, dans l'espace reseau propre d'un conteneur : connexion directe au proxy refusee pour l'utilisateur client et pour root, acceptee pour l'utilisateur de la passerelle, requete neutre a travers la passerelle reussie (200), compteur de rejets non nul. Un controle prealable verifie que le client joint le proxy avant la regle.
- Execute dans la CI GitHub Actions (noyau Ubuntu). Les noyaux sans nf_tables (certains bacs a sable) ignorent ce test seulement avec `LAB_LOCK_OPTIONAL=1`.
- Sans la regle, les quatre tests du verrou echouent (verifie en desactivant le chargement).
