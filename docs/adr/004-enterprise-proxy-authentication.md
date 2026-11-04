# ADR-004 - Sortie par proxy d'entreprise et authentification optionnelle

- Date : 2026-11-04
- Statut : accepte pour la conception ; implementation et integration a valider.

## Contexte

Toute sortie Internet doit emprunter un proxy d'entreprise. Deux variantes sont requises : sans authentification et avec NTLM/Kerberos. L'authentification du proxy est distincte de celle de GitHub Copilot.

## Decision

| Profil | Chemin |
|---|---|
| direct_proxy | passerelle PII -> proxy d'entreprise -> GitHub Copilot |
| integrated_proxy | passerelle PII -> Px local -> proxy d'entreprise NTLM/Kerberos -> GitHub Copilot |

Le terme direct_proxy signifie directement vers le proxy d'entreprise, jamais directement vers Internet.

Deleguer NTLM/Kerberos a Px plutot que reimplementer les handshakes dans le moteur PII. Privilegier le contexte SSPI Windows lorsqu'il est disponible et autorise. Valider l'identite effective en service, sous Linux, WSL ou en conteneur. Ne pas imposer de repli NTLM si Kerberos est obligatoire. Aucun mot de passe de domaine dans Git ou la configuration du moteur.

## Invariants

- Aucune bascule directe en cas de panne de Px, du proxy ou de l'authentification.
- Proxy amont Px explicite ; aucune exclusion externe noproxy/PAC non maitrisee.
- Verification TLS conservee, bundle CA approuve si inspection amont.
- Memes regles pour les appels sortants et les renouvellements de jetons geres par la passerelle.
- Les flux locaux de controle peuvent rester locaux sans creer d'exclusion externe.
- Une politique de sortie reseau est necessaire pour empecher les autres processus de contourner le chemin.

## Consequences

Le profil integrated_proxy ajoute un relais et un contexte d'identite a superviser. Distinguer les pannes de connexion, HTTP 407, TLS, filtre PII et Copilot. Une connexion reussie ne prouve pas quel mecanisme d'authentification a ete negocie.

## Validation

Tester chaque profil avec une destination approuvee ; confirmer l'identite et les journaux amont sans secrets ; verifier le canari PII et le routage Copilot ; arreter Px et l'amont pour prouver l'absence de repli direct.

## References

- https://github.com/genotrance/px
- https://docs.mitmproxy.org/stable/concepts/modes/
