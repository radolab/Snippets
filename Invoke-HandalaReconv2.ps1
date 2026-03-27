#Requires -Version 5.1
<#
.SYNOPSIS
    Invoke-HandalaRecon.ps1 — External Reconnaissance Orchestrator
    Phase 1 of Handala/Void Manticore TTP Emulation

.DESCRIPTION
    Performs comprehensive external reconnaissance against a target Entra ID tenant
    with zero authentication. Maps all domains, federation config, Azure resources,
    VPN/identity endpoints, and generates credential exposure hunting queries.
    
    All operations are unauthenticated and generate NO sign-in logs on the target tenant.

    Modules:
      1. Tenant Fingerprinting (AADInternals + raw API)
      2. Domain & Federation Mapping
      3. Certificate Transparency Log Mining
      4. Azure Subdomain / Resource Enumeration
      5. VPN & Identity Endpoint Identification
      6. Public Blob Storage Enumeration
      7. GitHub Dork & Secret Scan Query Generation
      8. Username Pattern Generation for Phase 2

.PARAMETER Domain
    Primary target domain (e.g., "stryker.com")

.PARAMETER OutputDir
    Directory for all output files. Created if it doesn't exist.
    Default: .\recon-<domain>-<date>

.PARAMETER SkipAADInternals
    Skip AADInternals module (if not installed). Falls back to raw API calls.

.PARAMETER SkipBlobEnum
    Skip Azure blob storage enumeration (can be slow).

.PARAMETER BlobBases
    Custom list of storage account name guesses. Default derives from domain.

.PARAMETER UsernameBases
    File containing base usernames (first.last format) for Phase 2 prep.
    If not provided, generates common admin/service account patterns only.

.EXAMPLE
    .\Invoke-HandalaRecon.ps1 -Domain "target.com"

.EXAMPLE
    .\Invoke-HandalaRecon.ps1 -Domain "target.com" -UsernameBases .\names.txt -OutputDir C:\engagements\target

.NOTES
    Author:  Red Team Operator Reference
    Context: Handala/Void Manticore TTP Emulation — Phase 1
    OPSEC:   All operations are completely passive to target SOC.
             No sign-in logs, no authentication events, no SIEM alerts.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Domain,

    [Parameter(Mandatory = $false)]
    [string]$OutputDir,

    [switch]$SkipAADInternals,
    [switch]$SkipBlobEnum,

    [Parameter(Mandatory = $false)]
    [string[]]$BlobBases,

    [Parameter(Mandatory = $false)]
    [string]$UsernameBases
)

# ============================================================
# CONFIGURATION
# ============================================================

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"  # Suppress progress bars for speed

if (-not $OutputDir) {
    $OutputDir = ".\recon-$($Domain.Replace('.','_'))-$(Get-Date -Format 'yyyyMMdd-HHmm')"
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

# Master results object — everything goes here
$Results = [ordered]@{
    Meta = [ordered]@{
        Target       = $Domain
        StartTime    = (Get-Date -Format "o")
        Operator     = $env:USERNAME
        Hostname     = $env:COMPUTERNAME
    }
    Tenant           = $null
    Domains          = @()
    Federation       = @()
    CertTransparency = @()
    AzureResources   = @()
    VPNEndpoints     = @()
    IdentityEndpoints = @()
    PublicBlobs      = @()
    GitHubDorks      = @()
    UsernameTargets  = @()
}

function Write-Phase {
    param([string]$Message)
    Write-Host "`n[*] $Message" -ForegroundColor Cyan
}

function Write-Finding {
    param([string]$Message)
    Write-Host "  [+] $Message" -ForegroundColor Green
}

function Write-Alert {
    param([string]$Message)
    Write-Host "  [!] $Message" -ForegroundColor Yellow
}

function Write-Fail {
    param([string]$Message)
    Write-Host "  [-] $Message" -ForegroundColor Red
}

function Save-Json {
    param([string]$Name, $Data)
    $path = Join-Path $OutputDir "$Name.json"
    $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $path -Encoding UTF8
    Write-Host "  [>] Saved: $path" -ForegroundColor DarkGray
}

# ============================================================
# MODULE 1: TENANT FINGERPRINTING
# ============================================================

Write-Phase "Module 1: Tenant Fingerprinting — $Domain"

# 1A: OpenID Configuration (always works, no dependencies)
$tenantInfo = [ordered]@{}
try {
    $openIdUrl = "https://login.microsoftonline.com/$Domain/.well-known/openid-configuration"
    $openId = Invoke-RestMethod -Uri $openIdUrl -Method Get -ErrorAction Stop
    
    $tenantId = ($openId.issuer -split '/')[-2]  # Extract GUID from issuer URL
    $tenantInfo.TenantId = $tenantId
    $tenantInfo.Region = $openId.tenant_region_scope
    $tenantInfo.CloudInstance = $openId.cloud_instance_name
    $tenantInfo.AuthorizationEndpoint = $openId.authorization_endpoint
    $tenantInfo.TokenEndpoint = $openId.token_endpoint
    
    Write-Finding "Tenant ID: $tenantId"
    Write-Finding "Region: $($openId.tenant_region_scope)"
}
catch {
    Write-Fail "OpenID config failed — domain may not be an Entra tenant: $_"
}

# 1B: User Realm Discovery
try {
    $realmUrl = "https://login.microsoftonline.com/getuserrealm.srf?login=user@$Domain&xml=1"
    [xml]$realm = (Invoke-WebRequest -Uri $realmUrl -ErrorAction Stop).Content
    
    $tenantInfo.NameSpaceType = $realm.RealmInfo.NameSpaceType
    $tenantInfo.FederationBrandName = $realm.RealmInfo.FederationBrandName
    $tenantInfo.CloudInstanceName = $realm.RealmInfo.CloudInstanceName
    $tenantInfo.DomainName = $realm.RealmInfo.DomainName
    
    if ($realm.RealmInfo.NameSpaceType -eq "Federated") {
        $tenantInfo.IsFederated = $true
        $tenantInfo.FederationProtocol = $realm.RealmInfo.FederationProtocol
        $tenantInfo.FederationMetadataUrl = $realm.RealmInfo.FederationMetadataUrl
        $tenantInfo.FederationActiveAuthUrl = $realm.RealmInfo.FederationActiveAuthUrl
        Write-Alert "Domain is FEDERATED — ADFS endpoint exposed (spray target)"
        Write-Alert "  IdP: $($realm.RealmInfo.FederationMetadataUrl)"
    }
    else {
        $tenantInfo.IsFederated = $false
        Write-Finding "Domain is MANAGED (cloud-only auth)"
    }
}
catch {
    Write-Fail "User realm discovery failed: $_"
}

# 1C: AADInternals Full Recon (if available)
$aadAvailable = $false
if (-not $SkipAADInternals) {
    try {
        Import-Module AADInternals -ErrorAction Stop
        $aadAvailable = $true
        Write-Finding "AADInternals loaded"
    }
    catch {
        Write-Alert "AADInternals not installed — using raw API fallback"
        Write-Alert "  Install: Install-Module AADInternals -Scope CurrentUser"
    }
}

if ($aadAvailable) {
    try {
        $aadRecon = Invoke-AADIntReconAsOutsider -DomainName $Domain
        
        $tenantInfo.TenantName = $aadRecon.TenantName
        $tenantInfo.TenantBrand = $aadRecon.TenantBrandName
        $tenantInfo.DesktopSSOEnabled = $aadRecon.DesktopSSOEnabled
        $tenantInfo.MDIInstance = $aadRecon.MDI
        $tenantInfo.DomainCount = ($aadRecon.Domains | Measure-Object).Count
        
        Write-Finding "Tenant Name: $($aadRecon.TenantName)"
        Write-Finding "Brand: $($aadRecon.TenantBrandName)"
        
        if ($aadRecon.DesktopSSOEnabled) {
            Write-Alert "Seamless SSO ENABLED — silent user enum available (Autologon method, zero logs)"
        }
        if ($aadRecon.MDI) {
            Write-Alert "Microsoft Defender for Identity DETECTED — credential theft detection likely"
        }
        
        # Extract all domains
        foreach ($d in $aadRecon.Domains) {
            $domainEntry = [ordered]@{
                Name               = $d.Name
                AuthenticationType = $d.AuthenticationType
                IsVerified         = $d.Verified
                IsFederated        = ($d.AuthenticationType -eq "Federated")
                FederationUrl      = $d.FederationUrl
                MX                 = $d.MX
                SPF                = $d.SPF
                DMARC              = $d.DMARC
                DNS                = $d.DNS
            }
            $Results.Domains += $domainEntry
            
            if ($d.AuthenticationType -eq "Federated") {
                Write-Alert "  $($d.Name) — FEDERATED → $($d.FederationUrl)"
                $Results.Federation += [ordered]@{
                    Domain        = $d.Name
                    FederationUrl = $d.FederationUrl
                    Protocol      = "WSTrust"
                }
            }
            else {
                Write-Finding "  $($d.Name) — Managed"
            }
        }
    }
    catch {
        Write-Fail "AADInternals recon failed: $_"
    }
}

$tenantInfo.DomainCount = ($Results.Domains | Measure-Object).Count
$Results.Tenant = $tenantInfo
Save-Json "01_tenant_info" $tenantInfo
Save-Json "01_domains" $Results.Domains

# ============================================================
# MODULE 2: CERTIFICATE TRANSPARENCY LOG MINING
# ============================================================

Write-Phase "Module 2: Certificate Transparency Logs"

try {
    $ctUrl = "https://crt.sh/?q=%25.$Domain&output=json"
    $ctRaw = Invoke-RestMethod -Uri $ctUrl -Method Get -ErrorAction Stop
    
    # Deduplicate and extract unique hostnames
    $ctDomains = $ctRaw | ForEach-Object { $_.name_value -split "`n" } |
        Sort-Object -Unique |
        Where-Object { $_ -match "^[a-zA-Z0-9\.\-\*]+$" -and $_ -notmatch "^\*\." }
    
    $Results.CertTransparency = $ctDomains
    Write-Finding "$($ctDomains.Count) unique hostnames from CT logs"
    
    # Flag interesting subdomains
    $vpnPatterns      = "vpn|remote|gateway|ssl|access|portal|citrix|pulse|forti|globalprotect|anyconnect|ra\."
    $idPatterns       = "adfs|sts|sso|login|auth|idp|okta|ping|saml|federation"
    $devPatterns      = "dev|staging|test|uat|sandbox|internal|lab|preprod"
    $ctAdminPatterns  = "admin|manage|intune|endpoint|mdm|sccm|autopilot"  # Renamed: avoids collision with Module 7 username array

    $vpnHits   = $ctDomains | Where-Object { $_ -match $vpnPatterns }
    $idHits    = $ctDomains | Where-Object { $_ -match $idPatterns }
    $devHits   = $ctDomains | Where-Object { $_ -match $devPatterns }
    $adminHits = $ctDomains | Where-Object { $_ -match $ctAdminPatterns }
    
    if ($vpnHits)   { $vpnHits   | ForEach-Object { Write-Alert "VPN/Remote: $_" }; $Results.VPNEndpoints += $vpnHits }
    if ($idHits)    { $idHits    | ForEach-Object { Write-Alert "Identity: $_" };     $Results.IdentityEndpoints += $idHits }
    if ($devHits)   { $devHits   | ForEach-Object { Write-Alert "Dev/Staging: $_" } }
    if ($adminHits) { $adminHits | ForEach-Object { Write-Alert "Admin/MDM: $_" } }
    
    Save-Json "02_ct_domains" $ctDomains
}
catch {
    Write-Fail "CT log query failed: $_"
}

# ============================================================
# MODULE 3: AZURE RESOURCE ENUMERATION
# ============================================================

Write-Phase "Module 3: Azure Resource Enumeration"

$baseName = ($Domain -split '\.')[0]
$azureSuffixes = @(
    ".blob.core.windows.net",        # Blob Storage
    ".file.core.windows.net",        # File Storage
    ".queue.core.windows.net",       # Queue Storage
    ".table.core.windows.net",       # Table Storage
    ".vault.azure.net",              # Key Vault
    ".azurewebsites.net",            # App Service
    ".scm.azurewebsites.net",        # App Service Kudu/SCM
    ".azurefd.net",                  # Front Door
    ".trafficmanager.net",           # Traffic Manager
    ".cloudapp.azure.com",           # Cloud Services
    ".database.windows.net",         # SQL Database
    ".documents.azure.com",          # Cosmos DB
    ".azurecr.io",                   # Container Registry
    ".redis.cache.windows.net",      # Redis Cache
    ".servicebus.windows.net",       # Service Bus
    "-my.sharepoint.com",            # OneDrive for Business
    ".sharepoint.com",               # SharePoint Online
    ".mail.protection.outlook.com"   # Exchange Online Protection
)

# Generate name variations
$nameVariations = @(
    $baseName,
    "${baseName}corp",
    "${baseName}inc",
    "${baseName}-prod",
    "${baseName}-dev",
    "${baseName}-staging",
    "${baseName}-backup",
    "${baseName}data",
    "${baseName}files",
    "${baseName}app",
    "${baseName}api",
    "${baseName}web"
)

$azureResources = @()
$totalChecks = $nameVariations.Count * $azureSuffixes.Count
$checked = 0

foreach ($name in $nameVariations) {
    foreach ($suffix in $azureSuffixes) {
        $checked++
        $fqdn = "$name$suffix"
        try {
            # GetHostEntry throws a terminating .NET exception on failure — caught below; 2>$null is ineffective on .NET calls
            $dns = [System.Net.Dns]::GetHostEntry($fqdn)
            if ($dns) {
                $resource = [ordered]@{
                    FQDN      = $fqdn
                    Name      = $name
                    Service   = ($suffix -replace '^\.|\..*$', '')
                    IPAddress = ($dns.AddressList | Select-Object -First 1).ToString()
                }
                $azureResources += $resource
                Write-Finding "RESOLVED: $fqdn → $($resource.IPAddress)"
            }
        }
        catch {
            # DNS resolution failed — resource doesn't exist, expected
        }
        
        if ($checked % 50 -eq 0) {
            Write-Host "  [$checked/$totalChecks] checked..." -ForegroundColor DarkGray
        }
    }
}

$Results.AzureResources = $azureResources
Write-Finding "$($azureResources.Count) Azure resources discovered"
Save-Json "03_azure_resources" $azureResources

# ============================================================
# MODULE 4: PUBLIC BLOB STORAGE ENUMERATION
# ============================================================

if (-not $SkipBlobEnum) {
    Write-Phase "Module 4: Public Blob Storage Check"
    
    if ($BlobBases) {
        $storageNames = $BlobBases
    }
    else {
        $storageNames = @($baseName, "${baseName}corp", "${baseName}data", "${baseName}backup",
                          "${baseName}dev", "${baseName}files", "${baseName}public",
                          "${baseName}export", "${baseName}uploads")
    }
    
    $containers = @("backup", "data", "logs", "export", "public", "uploads",
                    "config", "migration", "scripts", "images", "assets",
                    "documents", "files", "media", "static", "temp")
    
    $publicBlobs = @()
    
    foreach ($storage in $storageNames) {
        foreach ($container in $containers) {
            $url = "https://$storage.blob.core.windows.net/$container`?restype=container&comp=list"
            try {
                $response = Invoke-WebRequest -Uri $url -Method Get -ErrorAction Stop -TimeoutSec 5
                if ($response.StatusCode -eq 200) {
                    $blob = [ordered]@{
                        StorageAccount = $storage
                        Container      = $container
                        URL            = $url
                        Status         = "PUBLIC"
                        ContentLength  = $response.Headers.'Content-Length'
                    }
                    $publicBlobs += $blob
                    Write-Alert "PUBLIC BLOB: $url"
                }
            }
            catch {
                # 404 (not found) or 403 (private) — both expected, skip silently
            }
        }
    }
    
    $Results.PublicBlobs = $publicBlobs
    if ($publicBlobs.Count -gt 0) {
        Write-Alert "$($publicBlobs.Count) PUBLIC blob containers found!"
    }
    else {
        Write-Finding "No public blob containers found"
    }
    Save-Json "04_public_blobs" $publicBlobs
}

# ============================================================
# MODULE 5: FEDERATION ENDPOINT PROBING
# ============================================================

Write-Phase "Module 5: Federation & Identity Endpoint Probing"

$federationResults = @()

# Check each federated domain's IdP
foreach ($fed in $Results.Federation) {
    if ($fed.FederationUrl) {
        # Extract ADFS hostname from federation URL
        try {
            $adfsHost = ([System.Uri]$fed.FederationUrl).Host
        }
        catch {
            $adfsHost = $fed.FederationUrl
        }
        
        # Probe ADFS endpoints
        $adfsEndpoints = @(
            "https://$adfsHost/adfs/ls/idpinitiatedsignon.aspx",
            "https://$adfsHost/federationmetadata/2007-06/federationmetadata.xml",
            "https://$adfsHost/adfs/services/trust/2005/usernamemixed"   # Spray target — bypasses Entra Smart Lockout
        )
        
        foreach ($ep in $adfsEndpoints) {
            try {
                $r = Invoke-WebRequest -Uri $ep -Method Get -ErrorAction Stop -TimeoutSec 10 -MaximumRedirection 0
                $status = $r.StatusCode
            }
            catch {
                if ($_.Exception.Response) {
                    $status = [int]$_.Exception.Response.StatusCode
                }
                else {
                    $status = "TIMEOUT"
                }
            }
            
            $result = [ordered]@{
                Domain   = $fed.Domain
                Endpoint = $ep
                Status   = $status
                IsSprayTarget = ($ep -match "usernamemixed" -and $status -ne "TIMEOUT" -and $status -ne 404)
            }
            $federationResults += $result
            
            if ($result.IsSprayTarget) {
                Write-Alert "ADFS SPRAY TARGET: $ep (Status: $status)"
                Write-Alert "  This endpoint bypasses Entra Smart Lockout!"
            }
            else {
                Write-Finding "$ep → $status"
            }
        }
    }
}

Save-Json "05_federation_endpoints" $federationResults

# ============================================================
# MODULE 6: GITHUB DORK & SECRET SCAN QUERIES
# ============================================================

Write-Phase "Module 6: GitHub Dork Generation"

$orgName = $baseName
$dorks = @(
    # Azure / Entra secrets
    [ordered]@{ Query = "`"$Domain`" AZURE_CLIENT_SECRET";         Category = "Azure SP Secret" },
    [ordered]@{ Query = "`"$Domain`" client_secret";               Category = "Client Secret" },
    [ordered]@{ Query = "`"$Domain`" connectionstring";            Category = "Connection String" },
    [ordered]@{ Query = "org:$orgName filename:.env";              Category = "Env File" },
    [ordered]@{ Query = "org:$orgName filename:appsettings.json";  Category = "App Settings" },
    [ordered]@{ Query = "org:$orgName `"DefaultEndpointsProtocol`""; Category = "Storage Connection" },
    [ordered]@{ Query = "org:$orgName `"SharedAccessSignature`"";  Category = "SAS Token" },
    [ordered]@{ Query = "org:$orgName filename:terraform.tfstate"; Category = "Terraform State" },
    [ordered]@{ Query = "org:$orgName filename:.tfvars";           Category = "Terraform Vars" },
    [ordered]@{ Query = "org:$orgName path:.github/workflows `"AZURE`""; Category = "CI/CD Azure Creds" },
    [ordered]@{ Query = "`"$baseName.onmicrosoft.com`" password OR secret"; Category = "Tenant Creds" },
    [ordered]@{ Query = "`"$Domain`" password";                    Category = "Passwords" },
    [ordered]@{ Query = "org:$orgName `"tenant_id`" `"client_id`""; Category = "SP Credential Triplet" },
    
    # Intune / MDM specific
    [ordered]@{ Query = "org:$orgName intune OR `"device management`""; Category = "Intune Config" },
    [ordered]@{ Query = "org:$orgName `"graph.microsoft.com`" secret"; Category = "Graph API Secret" },
    
    # Infrastructure
    [ordered]@{ Query = "`"$Domain`" vpn password OR credential";  Category = "VPN Credentials" },
    [ordered]@{ Query = "org:$orgName filename:id_rsa";            Category = "SSH Private Key" },
    [ordered]@{ Query = "org:$orgName filename:.pem";              Category = "Certificate/Key" }
)

$Results.GitHubDorks = $dorks

# Generate TruffleHog commands
$trufflehogCmds = @(
    "# TruffleHog commands for $Domain",
    "# Run these from a system with trufflehog installed",
    "",
    "# Scan GitHub org (full history, all branches, verified only)",
    "trufflehog github --org=`"$orgName`" --results=verified --json > trufflehog-$orgName.json",
    "",
    "# Scan specific repos (add discovered repos here)",
    "# trufflehog github --repo=`"https://github.com/$orgName/REPO`" --results=verified",
    "",
    "# Scan Docker images (if published)",
    "# trufflehog docker --image=`"$orgName/IMAGE:latest`" --results=verified",
    "",
    "# Gitleaks alternative (faster, less thorough)",
    "# gitleaks detect --source=`"https://github.com/$orgName/REPO`" --report-format=json"
)

$dorks | ForEach-Object { Write-Finding "[$($_.Category)] $($_.Query)" }
$dorks | ForEach-Object { $_.SearchURL = "https://github.com/search?q=$([System.Uri]::EscapeDataString($_.Query))&type=code" }

Save-Json "06_github_dorks" $dorks
$trufflehogCmds | Out-File -FilePath (Join-Path $OutputDir "06_trufflehog_commands.txt") -Encoding UTF8

# ============================================================
# MODULE 7: USERNAME TARGET GENERATION
# ============================================================

Write-Phase "Module 7: Username Target Generation for Phase 2"

# Standard admin / service account patterns (always generated)
$adminPatterns = @(
    "admin", "administrator", "it-admin", "itadmin",
    "helpdesk", "servicedesk", "support",
    "svc-intune", "svc-azure", "svc-graph", "svc-entra",
    "intune-admin", "intuneadmin", "azureadmin", "globaladmin",
    "breakglass", "breakglass1", "breakglass2",
    "emergency", "emergency-admin",
    "sync", "aadsync", "entraconnect", "dirsync",
    "scanner", "noreply", "no-reply",
    "service", "svc-backup", "svc-monitor",
    "security", "secops", "soc",
    "devops", "cicd", "deploy", "automation",
    "test", "testuser", "qa"
)

$allUsernames = @()

# Generate across all discovered domains
$targetDomains = @($Domain)
if ($Results.Domains.Count -gt 0) {
    $targetDomains = $Results.Domains | Where-Object { $_.IsVerified -eq $true } | ForEach-Object { $_.Name }
}

foreach ($d in $targetDomains) {
    foreach ($pattern in $adminPatterns) {
        $allUsernames += "$pattern@$d"
    }
}

# If base username file provided, expand across all domains
if ($UsernameBases -and (Test-Path $UsernameBases)) {
    $baseNames = Get-Content $UsernameBases | Where-Object { $_.Trim() -ne "" }
    Write-Finding "Loaded $($baseNames.Count) base usernames from $UsernameBases"
    
    foreach ($d in $targetDomains) {
        foreach ($name in $baseNames) {
            $allUsernames += "$name@$d"
        }
    }
}

$allUsernames = $allUsernames | Sort-Object -Unique
$Results.UsernameTargets = $allUsernames
Write-Finding "$($allUsernames.Count) username targets generated across $($targetDomains.Count) domains"

$allUsernames | Out-File -FilePath (Join-Path $OutputDir "07_username_targets.txt") -Encoding UTF8
$adminPatterns | ForEach-Object { "$_@$Domain" } | Out-File -FilePath (Join-Path $OutputDir "07_admin_targets.txt") -Encoding UTF8

# ============================================================
# MODULE 8: SUMMARY & PHASE 2 HANDOFF
# ============================================================

Write-Phase "Recon Summary"

$summary = [ordered]@{
    Target              = $Domain
    TenantId            = $tenantInfo.TenantId
    TenantName          = $tenantInfo.TenantName
    Region              = $tenantInfo.Region
    SeamlessSSO         = $tenantInfo.DesktopSSOEnabled
    MDIDetected         = $tenantInfo.MDIInstance
    DomainsDiscovered   = $Results.Domains.Count
    FederatedDomains    = ($Results.Domains | Where-Object { $_.IsFederated }).Count
    ManagedDomains      = ($Results.Domains | Where-Object { -not $_.IsFederated }).Count
    CTHostnames         = $Results.CertTransparency.Count
    AzureResources      = $Results.AzureResources.Count
    VPNEndpoints        = $Results.VPNEndpoints.Count
    IdentityEndpoints   = $Results.IdentityEndpoints.Count
    PublicBlobs         = $Results.PublicBlobs.Count
    ADFSSprayTargets    = ($federationResults | Where-Object { $_.IsSprayTarget }).Count
    UsernameTargets     = $allUsernames.Count
    CompletedAt         = (Get-Date -Format "o")
}

# Recommended Phase 2 enumeration method
if ($tenantInfo.DesktopSSOEnabled) {
    $summary.RecommendedEnumMethod = "Autologon (zero logs — SSO enabled)"
}
else {
    $summary.RecommendedEnumMethod = "GetCredentialType or OneDrive (no sign-in logs)"
}

# Attack surface assessment
$attackSurface = @()
if ($summary.FederatedDomains -gt 0) {
    $attackSurface += "ADFS spray (bypasses Entra Smart Lockout)"
}
if ($summary.PublicBlobs -gt 0) {
    $attackSurface += "Public blob storage — check for config files, backups, credentials"
}
if ($summary.SeamlessSSO) {
    $attackSurface += "Silent user enumeration via Autologon (completely undetectable)"
}
if ($summary.VPNEndpoints -gt 0) {  # VPNEndpoints is already an integer count — .Count would return 1 for any int
    $attackSurface += "VPN endpoints exposed — Handala's primary initial access vector"
}
$summary.AttackSurface = $attackSurface

# Print summary
Write-Host "`n$('=' * 60)" -ForegroundColor White
Write-Host "  RECON COMPLETE: $Domain" -ForegroundColor White
Write-Host "$('=' * 60)" -ForegroundColor White
$summary.GetEnumerator() | Where-Object { $_.Key -ne "AttackSurface" } | ForEach-Object {
    $val = if ($null -eq $_.Value) { "N/A" } else { $_.Value }
    Write-Host "  $($_.Key.PadRight(25)) $val"
}

if ($attackSurface.Count -gt 0) {
    Write-Host "`n  Attack Surface Notes:" -ForegroundColor Yellow
    $attackSurface | ForEach-Object { Write-Host "    → $_" -ForegroundColor Yellow }
}

Write-Host "`n  Phase 2 Enum Method: $($summary.RecommendedEnumMethod)" -ForegroundColor Cyan
Write-Host "  Output: $OutputDir" -ForegroundColor DarkGray
Write-Host "$('=' * 60)`n" -ForegroundColor White

Save-Json "00_summary" $summary

# Save master results
Save-Json "99_full_results" $Results

$Results.Meta.EndTime = (Get-Date -Format "o")
Write-Host "[*] All output saved to: $OutputDir" -ForegroundColor Cyan
Write-Host "[*] Next: Run Invoke-HandalaUserEnum.ps1 with 07_username_targets.txt`n" -ForegroundColor Cyan
