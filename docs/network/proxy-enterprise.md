# Configuration du proxy d'entreprise

Voir [ADR-004](../adr/004-enterprise-proxy-authentication.md). Les exemples ci-dessous doivent etre adaptes et valides sur les versions installees.

## Sans authentification

Configuration mitmproxy :

```yaml
mode:
  - upstream:http://proxy.entreprise.example:8080
ssl_insecure: false
```

## NTLM/Kerberos via Px

Configuration Px :

```ini
[proxy]
server = proxy.entreprise.example:8080
listen = 127.0.0.1
port = 3128
```

Configuration mitmproxy :

```yaml
mode:
  - upstream:http://127.0.0.1:3128
ssl_insecure: false
```

L'authentification du proxy amont appartient a Px. Ne pas mettre les credentials de domaine dans upstream_auth de mitmproxy pour cette variante. Fixer explicitement le serveur amont et verifier les exclusions. Ne pas configurer de boucle vers la passerelle.

## TLS

Si le proxy inspecte HTTPS, fournir le bundle approuve :

```yaml
ssl_verify_upstream_trusted_ca: /chemin/ca-bundle-entreprise.pem
ssl_insecure: false
```

Ce bundle amont est distinct du certificat local d'interception mitmproxy que doit reconnaitre Copilot. Le transport natif aura une configuration distincte.

## Valider NTLM/Kerberos sur le poste (manuel, non bloquant)

Ce controle n'est ni automatise ni requis par le lab ou la CI. Il se fait une fois sur un poste autorise, avec une URL de test approuvee (exemple : `https://api.github.com/`), sans donnees reelles. Ne jamais saisir de mot de passe dans une ligne de commande ni dans un fichier versionne.

1. Identifier le mecanisme exige par le proxy, sans Px :

   ```bash
   curl -sv -o /dev/null -x http://proxy.entreprise.example:8080 https://api.github.com/ 2>&1 | grep -i -E '< HTTP|proxy-authenticate'
   ```

   Un 407 avec `Proxy-Authenticate: Negotiate` et/ou `NTLM` indique les methodes proposees.

2. Disposer d'une identite :
   - Windows : session du domaine ; Px utilise SSPI, rien a configurer.
   - macOS ou Linux : `kinit utilisateur@DOMAINE` puis `klist` pour verifier le ticket, que libcurl peut utiliser via GSS-API (a confirmer a l'etape 3). A defaut, enregistrer le mot de passe dans le trousseau (saisie interactive) avec `px --username='DOMAINE\utilisateur' --password`, ou laisser Px gerer le ticket avec `--kerberos=1`.

3. Tester Px seul : `make px-config`, adapter `server`, puis :

   ```bash
   .venv/bin/px --config=px.ini --test=https://api.github.com/
   ```

   Pour forcer un mecanisme : ajouter `--auth=NEGOTIATE` (Kerberos) ou `--auth=NTLM`. `--verbose` affiche les echanges sans les secrets ; ne pas conserver ces journaux.

4. Tester le chainage : `make px` dans un terminal, puis :

   ```bash
   curl -sI -x http://127.0.0.1:3128 https://api.github.com/ | head -1
   ```

   Attendu : une reponse de la destination, pas de 407.

5. Brancher la passerelle : mode `upstream:http://127.0.0.1:3128` dans config.yaml, `make run`, puis `make canary`. Arreter Px et verifier qu'aucune requete ne sort autrement (la passerelle doit renvoyer une erreur).

Consigner le resultat (OS, mecanisme, version de Px, date) dans la PR ou le handoff, sans identifiants. Un echec ici n'empeche pas le developpement : le lab utilise un proxy sans authentification.

## Schema cible V4, non implemente

```yaml
network:
  profile: integrated_proxy # direct_proxy | integrated_proxy
  require_proxy: true
  corporate_proxy:
    url: http://proxy.entreprise.example:8080
  integrated_auth:
    relay_url: http://127.0.0.1:3128
  tls:
    verify: true
    ca_bundle: null
```

Ne pas copier ce schema dans mitmproxy : il decrit la future application.

## Diagnostic

Verifier profil, port local, identite Px, absence de 407 persistant, confiance TLS, filtre charge, canari synthetique, requete Copilot observee, trafic amont et panne sans contournement. En environnement distant, verifier ou tourne l'hote d'extension. Ne pas supposer le SSO Windows disponible dans WSL ou un conteneur. Le choix NTLM/Kerberos et le compte de service doivent respecter la politique d'entreprise.
