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
