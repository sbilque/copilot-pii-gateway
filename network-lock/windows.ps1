# Verrou reseau Windows (pare-feu, ADR-009). NON VERIFIE dans ce depot.
# Le pare-feu Windows fait primer les regles de blocage : on bloque donc VS Code vers le
# proxy d'entreprise, au lieu d'autoriser seulement la passerelle. A executer en
# administrateur, avec l'accord de l'equipe securite. Adapter le chemin et l'adresse.
$Proxy = "10.0.0.10"
$ProxyPort = 3128
$Code = "$env:LOCALAPPDATA\Programs\Microsoft VS Code\Code.exe"

New-NetFirewallRule -DisplayName "Copilot PII: VS Code direct to proxy" `
    -Direction Outbound -Action Block -Protocol TCP `
    -Program $Code -RemoteAddress $Proxy -RemotePort $ProxyPort
