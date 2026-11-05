# Verrou reseau

Exemples pour empecher VS Code de joindre le proxy d'entreprise sans passer par la passerelle (ADR-009). A appliquer par l'administrateur du poste, avec l'accord de la securite.

| Fichier | Systeme | Etat |
|---|---|---|
| `linux.nft` | Linux, nftables | Verifie dans le lab (CI) |
| `macos.pf` | macOS, pf | Non verifie |
| `windows.ps1` | Windows, pare-feu | Non verifie |

Prerequis : la passerelle tourne sous un utilisateur dedie, distinct de celui de VS Code.

## Linux

```bash
sudo useradd --system --create-home copilot-gw
# Adapter PROXY, PROXY_PORT et GATEWAY_UID (id -u copilot-gw) dans linux.nft
sudo nft -f network-lock/linux.nft
```

Persistance : inclure le fichier depuis `/etc/nftables.conf`. Retrait : `sudo nft delete table inet copilot_pii_lock`.

## macOS

Creer l'utilisateur dedie `_copilotgw`, copier `macos.pf` dans `/etc/pf.anchors/copilot-pii`, puis ajouter a `/etc/pf.conf` :

```text
anchor "copilot-pii"
load anchor "copilot-pii" from "/etc/pf.anchors/copilot-pii"
```

Charger : `sudo pfctl -f /etc/pf.conf -e`. Le mot-cle `user` ne s'applique qu'a TCP et UDP ([pf.conf, macOS](https://man.freebsd.org/cgi/man.cgi?query=pf.conf&sektion=5&manpath=macOS+14.8)).

## Windows

En administrateur : `powershell -File network-lock\windows.ps1`, apres adaptation. La regle bloque `Code.exe` vers le proxy ([New-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule)).

## Verifier

Avec des donnees synthetiques, depuis l'utilisateur de VS Code :

1. Connexion directe au proxy : refus immediat attendu (`curl -x http://PROXY:PORT https://api.business.githubcopilot.com` echoue avec connexion refusee).
2. Depuis l'utilisateur dedie, la meme connexion TCP aboutit.
3. `make canary` (via la passerelle) affiche `ready=true`.
4. Linux : `sudo nft list table inet copilot_pii_lock` montre un compteur de rejets non nul.
