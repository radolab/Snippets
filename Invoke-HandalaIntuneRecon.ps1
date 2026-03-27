#Requires -Version 5.1
<#
.SYNOPSIS
    Invoke-HandalaIntuneRecon.ps1 — Service Principal Enumeration & Intune Reconnaissance
    Phase 4 of Handala/Void Manticore TTP Emulation

.DESCRIPTION
    Authenticated enumeration via a compromised service principal token.
    Performs comprehensive directory dump and Intune-specific reconnaissance
    to assess the "blast radius" of a potential Stryker-style MDM weaponization attack.

    All operations are READ-ONLY by default. The script:
      1. Dumps users, groups, directory roles, admin role members
      2. Enumerates all app registrations, service principals, OAuth2 grants
      3. Maps Conditional Access policies and identifies gaps for workload identities
      4. Enumerates Intune managed devices (blast radius count)
      5. Inventories Intune scripts, configs, compliance policies, apps
      6. Identifies escalation paths from current SP permissions
      7. Checks Multi-Admin Approval (MAA) configuration
      8. Generates Stryker-scenario risk assessment

    OPSEC: Token acquisition generates ONE service principal sign-in log entry.
    All subsequent Graph API read calls are NOT individually audited.
    Detection risk: LOW.

.PARAMETER Token
    Pre-acquired Graph API access token (Bearer token string).
    Use this if you already have a token from Script 3 or manual acquisition.

.PARAMETER ClientId
    Service principal client ID. Used with -ClientSecret and -TenantId to acquire token.

.PARAMETER ClientSecret
    Service principal client secret.

.PARAMETER TenantId
    Target tenant ID.

.PARAMETER SPCredFile
    Path to Script 3 output (09_sp_validation.json). Auto-selects the highest-privilege
    live SP and acquires a fresh token.

.PARAMETER OutputDir
    Output directory. Default: current directory or ReconDir.

.PARAMETER ReconDir
    Phase 1-3 output directory. Inherits location and enriches existing data.

.PARAMETER MaxUsers
    Maximum users to enumerate. Default: 50000. Set lower for large tenants during testing.

.PARAMETER ThrottleMs
    Delay between paginated Graph API requests in milliseconds. Default: 300.
    Increase if hitting 429 throttle responses.

.EXAMPLE
    # Use token directly
    .\Invoke-HandalaIntuneRecon.ps1 -Token "eyJ0eX..."

.EXAMPLE
    # Authenticate with SP credentials
    .\Invoke-HandalaIntuneRecon.ps1 -ClientId "xxx" -ClientSecret "xxx" -TenantId "xxx"

.EXAMPLE
    # Auto-select best SP from Script 3 output
    .\Invoke-HandalaIntuneRecon.ps1 -SPCredFile .\09_sp_validation.json -ReconDir .\recon-target

.NOTES
    All operations are READ-ONLY. No write operations are performed.
    No devices are wiped, no scripts are deployed, no policies are modified.
    This script assesses the POTENTIAL for a Stryker-style attack — it does not execute one.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Token,

    [Parameter(Mandatory = $false)]
    [string]$ClientId,

    [Parameter(Mandatory = $false)]
    [string]$ClientSecret,

    [Parameter(Mandatory = $false)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [string]$SPCredFile,

    [Parameter(Mandatory = $false)]
    [string]$OutputDir,

    [Parameter(Mandatory = $false)]
    [string]$ReconDir,

    [int]$MaxUsers = 50000,
    [int]$ThrottleMs = 300
)

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

# ============================================================
# HELPERS
# ============================================================

function Write-Phase    { param([string]$M) Write-Host "`n[*] $M" -ForegroundColor Cyan }
function Write-Finding  { param([string]$M) Write-Host "  [+] $M" -ForegroundColor Green }
function Write-Alert    { param([string]$M) Write-Host "  [!] $M" -ForegroundColor Yellow }
function Write-Fail     { param([string]$M) Write-Host "  [-] $M" -ForegroundColor Red }
function Write-Critical { param([string]$M) Write-Host "  [!!!] $M" -ForegroundColor Red -BackgroundColor Black }

function Save-Json {
    param([string]$Name, $Data)
    $path = Join-Path $script:OutputDir "$Name.json"
    $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $path -Encoding UTF8
    Write-Host "  [>] Saved: $path" -ForegroundColor DarkGray
}

function Invoke-GraphGet {
    <#
    .SYNOPSIS
        Paginated Graph API GET with throttle handling.
        Returns all items across all pages.
    #>
    param(
        [string]$Endpoint,
        [string]$Label = "items",
        [switch]$Beta,
        [int]$MaxItems = 0
    )

    $baseUrl = if ($Beta) { "https://graph.microsoft.com/beta" } else { "https://graph.microsoft.com/v1.0" }
    $url = if ($Endpoint.StartsWith("http")) { $Endpoint } else { "$baseUrl$Endpoint" }
    $allItems = @()

    while ($url) {
        try {
            $response = Invoke-RestMethod -Uri $url -Headers $script:Headers -Method Get -ErrorAction Stop
            $items = @()
            if ($response.value) { $items = @($response.value) }
            $allItems += $items
            $url = $response.'@odata.nextLink'

            if ($MaxItems -gt 0 -and $allItems.Count -ge $MaxItems) {
                $allItems = $allItems[0..($MaxItems - 1)]
                $url = $null
            }

            if ($url) { Start-Sleep -Milliseconds $script:ThrottleMs }
        }
        catch {
            $statusCode = 0
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }

            if ($statusCode -eq 429) {
                $retryAfter = 30
                try { $retryAfter = [int]$_.Exception.Response.Headers['Retry-After'] } catch {}
                Write-Alert "Throttled on $Label — waiting ${retryAfter}s"
                Start-Sleep -Seconds $retryAfter
                continue
            }
            elseif ($statusCode -eq 403) {
                Write-Fail "$Label — Access denied (insufficient permissions)"
                return @()
            }
            elseif ($statusCode -eq 404) {
                Write-Fail "$Label — Endpoint not found"
                return @()
            }
            else {
                Write-Fail "$Label — Error $statusCode : $($_.Exception.Message.Substring(0, [Math]::Min(150, $_.Exception.Message.Length)))"
                $url = $null
            }
        }
    }

    Write-Finding "$Label : $($allItems.Count)"
    return $allItems
}

# ============================================================
# AUTHENTICATION
# ============================================================

if (-not $OutputDir) {
    if ($ReconDir -and (Test-Path $ReconDir)) { $OutputDir = $ReconDir }
    else { $OutputDir = ".\intunerecon-$(Get-Date -Format 'yyyyMMdd-HHmm')" }
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

Write-Phase "Authentication"

# Priority: explicit Token > ClientId/Secret > SPCredFile auto-select
if (-not $Token) {
    if ($ClientId -and $ClientSecret -and $TenantId) {
        Write-Host "  Acquiring token for SP: $ClientId" -ForegroundColor DarkGray
        try {
            $tokenBody = @{
                grant_type    = "client_credentials"
                client_id     = $ClientId
                client_secret = $ClientSecret
                scope         = "https://graph.microsoft.com/.default"
            }
            $tokenResp = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
                -Method Post -Body $tokenBody -ErrorAction Stop
            $Token = $tokenResp.access_token
            Write-Finding "Token acquired"
        }
        catch {
            Write-Fail "Token acquisition failed: $_"
            return
        }
    }
    elseif ($SPCredFile -and (Test-Path $SPCredFile)) {
        Write-Host "  Auto-selecting best SP from Script 3 output..." -ForegroundColor DarkGray
        $spData = Get-Content $SPCredFile -Raw | ConvertFrom-Json

        # Pick highest-privilege live SP: CRITICAL > HIGH > MEDIUM, prefer Intune access
        $liveSPs = $spData | Where-Object { $_.IsLive -eq $true }
        $bestSP = $liveSPs |
            Sort-Object @{e={
                switch ($_.RiskLevel) { "CRITICAL" {0} "HIGH" {1} "MEDIUM" {2} default {3} }
            }}, @{e={ if ($_.IntuneAccess) {0} else {1} }} |
            Select-Object -First 1

        if (-not $bestSP) {
            Write-Fail "No live SPs found in $SPCredFile"
            return
        }

        Write-Finding "Selected SP: $($bestSP.ClientId) (Risk: $($bestSP.RiskLevel))"

        # Need original credentials — read from the input JSON used in Script 3
        # SPCredFile from Script 3 output doesn't store secrets, so we need the original input
        Write-Alert "Auto-select found best SP but cannot extract secret from Script 3 output."
        Write-Alert "Provide credentials directly: -ClientId '$($bestSP.ClientId)' -TenantId '$($bestSP.TenantId)' -ClientSecret <secret>"
        return
    }
    else {
        Write-Fail "No credentials provided. Use -Token, -ClientId/-ClientSecret/-TenantId, or -SPCredFile."
        return
    }
}

$script:Headers = @{
    "Authorization"    = "Bearer $Token"
    "ConsistencyLevel" = "eventual"
}
$script:OutputDir = $OutputDir
$script:ThrottleMs = $ThrottleMs

# Quick validation — try /organization endpoint
try {
    $org = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/organization" `
        -Headers $script:Headers -Method Get -ErrorAction Stop
    $tenantDisplayName = $org.value[0].displayName
    $tenantVerifiedDomains = $org.value[0].verifiedDomains | ForEach-Object { $_.name }
    Write-Finding "Connected to tenant: $tenantDisplayName"
    Write-Finding "Verified domains: $($tenantVerifiedDomains -join ', ')"
}
catch {
    Write-Alert "Cannot read /organization — limited permissions. Continuing with available access."
}

# ============================================================
# MODULE 1: DIRECTORY ENUMERATION
# ============================================================

Write-Phase "Module 1: Directory Enumeration"

# 1A: Users
$users = Invoke-GraphGet -Endpoint "/users?`$select=id,userPrincipalName,displayName,mail,jobTitle,department,accountEnabled,userType,onPremisesSyncEnabled,createdDateTime,lastPasswordChangeDateTime&`$top=999" `
    -Label "Users" -MaxItems $MaxUsers
Save-Json "12_users" $users

# Quick stats
$enabledUsers   = @($users | Where-Object { $_.accountEnabled -eq $true })
$syncedUsers    = @($users | Where-Object { $_.onPremisesSyncEnabled -eq $true })
$guestUsers     = @($users | Where-Object { $_.userType -eq "Guest" })
$cloudOnlyUsers = @($users | Where-Object { $_.onPremisesSyncEnabled -ne $true -and $_.userType -ne "Guest" })

Write-Finding "  Enabled: $($enabledUsers.Count) | Synced: $($syncedUsers.Count) | Cloud-only: $($cloudOnlyUsers.Count) | Guests: $($guestUsers.Count)"

# 1B: Directory Roles and Members
Write-Phase "Module 1B: Admin Role Membership"
$roles = Invoke-GraphGet -Endpoint "/directoryRoles?`$expand=members" -Label "Directory Roles"

$adminMap = @()
foreach ($role in $roles) {
    $members = @($role.members)
    if ($members.Count -eq 0) { continue }

    foreach ($member in $members) {
        $entry = [ordered]@{
            RoleName  = $role.displayName
            RoleId    = $role.id
            MemberUPN = $member.userPrincipalName
            MemberName = $member.displayName
            MemberId  = $member.id
            MemberType = $member.'@odata.type'
            IsServicePrincipal = ($member.'@odata.type' -eq "#microsoft.graph.servicePrincipal")
        }
        $adminMap += $entry
    }

    $memberList = ($members | ForEach-Object {
        if ($_.userPrincipalName) { $_.userPrincipalName } else { "$($_.displayName) [SP]" }
    }) -join ", "

    # Highlight critical roles
    if ($role.displayName -match "Global Administrator|Intune Administrator|Privileged Role") {
        Write-Alert "$($role.displayName) ($($members.Count)): $memberList"
    }
    else {
        Write-Finding "$($role.displayName) ($($members.Count)): $memberList"
    }
}
Save-Json "12_admin_roles" $adminMap

# Count key roles
$globalAdmins = @($adminMap | Where-Object { $_.RoleName -eq "Global Administrator" })
$intuneAdmins = @($adminMap | Where-Object { $_.RoleName -eq "Intune Administrator" })
$privRoleAdmins = @($adminMap | Where-Object { $_.RoleName -eq "Privileged Role Administrator" })
$appAdmins = @($adminMap | Where-Object { $_.RoleName -match "Application Administrator|Cloud Application Administrator" })

Write-Host ""
Write-Alert "Global Administrators:      $($globalAdmins.Count)"
Write-Alert "Intune Administrators:       $($intuneAdmins.Count)"
Write-Alert "Privileged Role Admins:      $($privRoleAdmins.Count)"
Write-Alert "App/Cloud App Admins:        $($appAdmins.Count)"

# 1C: Groups
Write-Phase "Module 1C: Groups"
$groups = Invoke-GraphGet -Endpoint "/groups?`$select=id,displayName,description,groupTypes,membershipRule,securityEnabled,mailEnabled,membershipRuleProcessingState&`$top=999" -Label "Groups"
Save-Json "12_groups" $groups

# Flag interesting groups
$interestingKeywords = "admin|intune|globaladmin|breakglass|privileged|paw|tier0|emergency|device|mdm|endpoint|autopilot|compliance|helpdesk"
$interestingGroups = @($groups | Where-Object { $_.displayName -match $interestingKeywords })
if ($interestingGroups.Count -gt 0) {
    Write-Alert "Interesting groups ($($interestingGroups.Count)):"
    $interestingGroups | ForEach-Object {
        $dynamic = if ($_.membershipRule) { " [DYNAMIC: $($_.membershipRule)]" } else { "" }
        Write-Host "    $($_.displayName)$dynamic" -ForegroundColor Yellow
    }
}

# ============================================================
# MODULE 2: APPLICATION & SERVICE PRINCIPAL INVENTORY
# ============================================================

Write-Phase "Module 2: Applications & Service Principals"

# 2A: App Registrations
$apps = Invoke-GraphGet -Endpoint "/applications?`$select=id,appId,displayName,passwordCredentials,keyCredentials,requiredResourceAccess,signInAudience&`$top=999" -Label "App Registrations"
Save-Json "13_applications" $apps

# Find apps with active credentials
$appsWithSecrets = @()
foreach ($app in $apps) {
    $activePwCreds = @($app.passwordCredentials | Where-Object {
        $null -eq $_.endDateTime -or [datetime]$_.endDateTime -gt (Get-Date)
    })
    $activeKeyCreds = @($app.keyCredentials | Where-Object {
        $null -eq $_.endDateTime -or [datetime]$_.endDateTime -gt (Get-Date)
    })

    if ($activePwCreds.Count -gt 0 -or $activeKeyCreds.Count -gt 0) {
        $appsWithSecrets += [ordered]@{
            DisplayName   = $app.displayName
            AppId         = $app.appId
            ActiveSecrets = $activePwCreds.Count
            ActiveCerts   = $activeKeyCreds.Count
            SignInAudience = $app.signInAudience
        }
    }
}

if ($appsWithSecrets.Count -gt 0) {
    Write-Alert "Apps with active credentials: $($appsWithSecrets.Count)"
    $appsWithSecrets | ForEach-Object {
        Write-Host "    $($_.DisplayName) — $($_.ActiveSecrets) secrets, $($_.ActiveCerts) certs" -ForegroundColor DarkGray
    }
}
Save-Json "13_apps_with_credentials" $appsWithSecrets

# 2B: Service Principals
$sps = Invoke-GraphGet -Endpoint "/servicePrincipals?`$select=id,appId,displayName,servicePrincipalType,accountEnabled&`$top=999" -Label "Service Principals"
Save-Json "13_service_principals" $sps

# ============================================================
# MODULE 3: CONDITIONAL ACCESS POLICY ANALYSIS
# ============================================================

Write-Phase "Module 3: Conditional Access Policies"

$caPolicies = Invoke-GraphGet -Endpoint "/identity/conditionalAccess/policies" -Label "CA Policies"
Save-Json "14_conditional_access" $caPolicies

if ($caPolicies.Count -gt 0) {
    $caAnalysis = @()

    foreach ($policy in $caPolicies) {
        $state = $policy.state
        $grant = $policy.grantControls
        $conditions = $policy.conditions

        $analysis = [ordered]@{
            Name               = $policy.displayName
            State              = $state
            TargetsAdmins      = $false
            TargetsAllUsers    = $false
            RequiresMFA        = $false
            RequiresCompliant  = $false
            RequiresFIDO2      = $false
            BlocksLegacyAuth   = $false
            CoversWorkloads    = $false
            ExcludesBreakglass = $false
            Gaps               = @()
        }

        # Check user scope
        $includeUsers = $conditions.users.includeUsers
        $includeRoles = $conditions.users.includeRoles
        $excludeUsers = $conditions.users.excludeUsers

        if ($includeUsers -contains "All") { $analysis.TargetsAllUsers = $true }
        if ($includeRoles.Count -gt 0) { $analysis.TargetsAdmins = $true }
        if ($excludeUsers.Count -gt 0) { $analysis.ExcludesBreakglass = $true }

        # Check grant controls
        if ($grant.builtInControls -contains "mfa") { $analysis.RequiresMFA = $true }
        if ($grant.builtInControls -contains "compliantDevice") { $analysis.RequiresCompliant = $true }
        if ($grant.authenticationStrength) { $analysis.RequiresFIDO2 = $true }

        # Check client app types (legacy auth blocking)
        $clientApps = $conditions.clientAppTypes
        if ($clientApps -contains "exchangeActiveSync" -or $clientApps -contains "other") {
            if ($grant.builtInControls -contains "block") { $analysis.BlocksLegacyAuth = $true }
        }

        # Check if policy covers workload identities (service principals)
        $clientAppTypes = $conditions.clientAppTypes
        if ($conditions.clientApplications -or ($clientAppTypes -and $clientAppTypes -contains "servicePrincipal")) {
            $analysis.CoversWorkloads = $true
        }

        # Gap identification
        if ($state -eq "enabled" -and $analysis.TargetsAllUsers -and -not $analysis.RequiresMFA) {
            $analysis.Gaps += "Targets all users but does not require MFA"
        }
        if ($state -eq "enabled" -and -not $analysis.CoversWorkloads) {
            $analysis.Gaps += "Does not cover workload identities (service principals)"
        }

        $caAnalysis += $analysis
    }

    Save-Json "14_ca_analysis" $caAnalysis

    # Summary
    $enabledPolicies = @($caAnalysis | Where-Object { $_.State -eq "enabled" })
    $mfaPolicies = @($enabledPolicies | Where-Object { $_.RequiresMFA })
    $workloadPolicies = @($enabledPolicies | Where-Object { $_.CoversWorkloads })
    $fidoPolicies = @($enabledPolicies | Where-Object { $_.RequiresFIDO2 })

    Write-Finding "Total policies: $($caPolicies.Count) (Enabled: $($enabledPolicies.Count))"
    Write-Finding "MFA-requiring:  $($mfaPolicies.Count)"
    Write-Finding "FIDO2-requiring: $($fidoPolicies.Count)"

    if ($workloadPolicies.Count -eq 0) {
        Write-Critical "NO CA policies cover workload identities (service principals)"
        Write-Critical "SP authentication bypasses ALL Conditional Access — Stryker-relevant gap"
    }
    else {
        Write-Finding "Workload identity policies: $($workloadPolicies.Count)"
    }

    # Report policies with gaps
    $gappyPolicies = @($caAnalysis | Where-Object { $_.Gaps.Count -gt 0 })
    if ($gappyPolicies.Count -gt 0) {
        Write-Alert "Policies with gaps ($($gappyPolicies.Count)):"
        $gappyPolicies | ForEach-Object {
            Write-Host "    $($_.Name):" -ForegroundColor Yellow
            $_.Gaps | ForEach-Object { Write-Host "      → $_" -ForegroundColor DarkGray }
        }
    }
}

# ============================================================
# MODULE 4: ENTRA ID DEVICE INVENTORY
# ============================================================

Write-Phase "Module 4: Entra ID Devices"

$devices = Invoke-GraphGet -Endpoint "/devices?`$select=id,displayName,operatingSystem,operatingSystemVersion,trustType,isManaged,isCompliant,registrationDateTime,approximateLastSignInDateTime&`$top=999" -Label "Entra Devices"
Save-Json "15_entra_devices" $devices

if ($devices.Count -gt 0) {
    $deviceStats = @{}
    $devices | ForEach-Object {
        $os = if ($_.operatingSystem) { $_.operatingSystem } else { "Unknown" }
        $deviceStats[$os] = ($deviceStats[$os] ?? 0) + 1
    }
    Write-Finding "Device OS breakdown:"
    $deviceStats.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
        Write-Host "    $($_.Key): $($_.Value)" -ForegroundColor DarkGray
    }

    $managedCount = @($devices | Where-Object { $_.isManaged -eq $true }).Count
    $compliantCount = @($devices | Where-Object { $_.isCompliant -eq $true }).Count
    Write-Finding "Managed: $managedCount | Compliant: $compliantCount"
}

# ============================================================
# MODULE 5: INTUNE MDM RECONNAISSANCE
# ============================================================

Write-Phase "Module 5: Intune MDM Reconnaissance (Blast Radius Assessment)"

# 5A: Managed Devices — this is the blast radius
$managedDevices = Invoke-GraphGet -Endpoint "/deviceManagement/managedDevices?`$select=id,deviceName,operatingSystem,osVersion,userPrincipalName,managementAgent,complianceState,enrolledDateTime,lastSyncDateTime,model,manufacturer&`$top=999" `
    -Label "Intune Managed Devices" -Beta

Save-Json "16_intune_managed_devices" $managedDevices

$intuneStats = [ordered]@{
    TotalManagedDevices   = $managedDevices.Count
    ByOS                  = @{}
    ByComplianceState     = @{}
    ByManagementAgent     = @{}
    RecentlySynced_24h    = 0
    RecentlySynced_7d     = 0
    UniqueUsers           = 0
}

if ($managedDevices.Count -gt 0) {
    # OS breakdown
    $managedDevices | ForEach-Object {
        $os = if ($_.operatingSystem) { $_.operatingSystem } else { "Unknown" }
        $intuneStats.ByOS[$os] = ($intuneStats.ByOS[$os] ?? 0) + 1
    }

    # Compliance breakdown
    $managedDevices | ForEach-Object {
        $state = if ($_.complianceState) { $_.complianceState } else { "Unknown" }
        $intuneStats.ByComplianceState[$state] = ($intuneStats.ByComplianceState[$state] ?? 0) + 1
    }

    # Management agent breakdown
    $managedDevices | ForEach-Object {
        $agent = if ($_.managementAgent) { $_.managementAgent } else { "Unknown" }
        $intuneStats.ByManagementAgent[$agent] = ($intuneStats.ByManagementAgent[$agent] ?? 0) + 1
    }

    # Sync recency
    $now = Get-Date
    $intuneStats.RecentlySynced_24h = @($managedDevices | Where-Object {
        $_.lastSyncDateTime -and ([datetime]$_.lastSyncDateTime) -gt $now.AddHours(-24)
    }).Count
    $intuneStats.RecentlySynced_7d = @($managedDevices | Where-Object {
        $_.lastSyncDateTime -and ([datetime]$_.lastSyncDateTime) -gt $now.AddDays(-7)
    }).Count

    # Unique users
    $intuneStats.UniqueUsers = ($managedDevices | Where-Object { $_.userPrincipalName } |
        Select-Object -ExpandProperty userPrincipalName -Unique).Count

    Write-Host ""
    Write-Critical "BLAST RADIUS: $($managedDevices.Count) managed devices"
    Write-Alert   "  Synced in last 24h: $($intuneStats.RecentlySynced_24h) (would receive wipe command immediately)"
    Write-Alert   "  Synced in last 7d:  $($intuneStats.RecentlySynced_7d)"
    Write-Alert   "  Unique users:       $($intuneStats.UniqueUsers)"
    Write-Host ""
    Write-Finding "OS breakdown:"
    $intuneStats.ByOS.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
        Write-Host "    $($_.Key): $($_.Value)" -ForegroundColor DarkGray
    }
    Write-Finding "Compliance state:"
    $intuneStats.ByComplianceState.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
        Write-Host "    $($_.Key): $($_.Value)" -ForegroundColor DarkGray
    }
}

Save-Json "16_intune_stats" $intuneStats

# 5B: Intune Configurations
Write-Phase "Module 5B: Intune Configurations & Scripts"

$intuneConfigs = [ordered]@{}

$configEndpoints = [ordered]@{
    "Device Configurations"   = "/deviceManagement/deviceConfigurations"
    "Compliance Policies"     = "/deviceManagement/deviceCompliancePolicies"
    "PowerShell Scripts"      = "/deviceManagement/deviceManagementScripts"
    "Shell Scripts (macOS)"   = "/deviceManagement/deviceShellScripts"
    "Win32 Apps"              = "/deviceAppManagement/mobileApps?`$filter=isof('microsoft.graph.win32LobApp')"
    "Autopilot Profiles"      = "/deviceManagement/windowsAutopilotDeploymentProfiles"
    "Config Profiles (new)"   = "/deviceManagement/configurationPolicies"
}

foreach ($entry in $configEndpoints.GetEnumerator()) {
    $data = Invoke-GraphGet -Endpoint $entry.Value -Label $entry.Key -Beta
    $intuneConfigs[$entry.Key] = $data.Count
    if ($data.Count -gt 0) {
        Save-Json "17_intune_$($entry.Key -replace ' ','_' -replace '[()]','')" $data
    }
}

# 5C: Check for "All Devices" or "All Users" assignment groups
Write-Phase "Module 5C: Broad Assignment Groups"

$broadGroups = @($groups | Where-Object {
    $_.displayName -match "^All (Devices|Users|Company|Corporate|Managed)" -or
    ($_.membershipRule -and $_.membershipRule -match "device\.deviceOSType|user\.userType")
})

if ($broadGroups.Count -gt 0) {
    Write-Alert "Broad-scope groups (potential wipe targets):"
    $broadGroups | ForEach-Object {
        $rule = if ($_.membershipRule) { " → Rule: $($_.membershipRule)" } else { "" }
        Write-Host "    $($_.displayName)$rule" -ForegroundColor Yellow
    }
}

# ============================================================
# MODULE 6: MULTI-ADMIN APPROVAL (MAA) CHECK
# ============================================================

Write-Phase "Module 6: Multi-Admin Approval Configuration"

# MAA is configured via /deviceManagement/operationApprovalPolicies (beta)
$maaPolicies = Invoke-GraphGet -Endpoint "/deviceManagement/operationApprovalPolicies" -Label "MAA Policies" -Beta

if ($maaPolicies.Count -gt 0) {
    Write-Finding "Multi-Admin Approval policies found: $($maaPolicies.Count)"
    Save-Json "18_maa_policies" $maaPolicies

    $maaPolicies | ForEach-Object {
        Write-Host "    $($_.displayName) — Approvers: $($_.approverGroupIds.Count)" -ForegroundColor DarkGray
    }
}
else {
    Write-Critical "NO Multi-Admin Approval policies configured!"
    Write-Critical "A single compromised Intune admin can wipe ALL devices without approval"
    Write-Critical "This is the exact gap exploited in the Stryker attack"
}

# ============================================================
# MODULE 7: ESCALATION PATH ANALYSIS
# ============================================================

Write-Phase "Module 7: Escalation Path Analysis"

# Decode our own token to check current permissions
$tokenParts = $Token.Split('.')
$payload = $tokenParts[1]
switch ($payload.Length % 4) { 2 { $payload += '==' } 3 { $payload += '=' } }
$payload = $payload.Replace('-', '+').Replace('_', '/')
$claims = $null
try {
    $bytes = [Convert]::FromBase64String($payload)
    $claims = [System.Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
}
catch {}

$currentRoles = @()
if ($claims -and $claims.roles) { $currentRoles = @($claims.roles) }

$escalationPaths = @()

# Path 1: Application.ReadWrite.All → self-grant Intune permissions
if ($currentRoles -contains "Application.ReadWrite.All") {
    $escalationPaths += [ordered]@{
        Path        = "Application.ReadWrite.All → Self-grant DeviceManagement*.ReadWrite.All"
        Risk        = "CRITICAL"
        Description = "Can add appRoleAssignment to grant self Intune admin permissions via Graph API"
        MandiantRef = "Abusing Intune Permissions for Lateral Movement (Nov 2024)"
    }
}

# Path 2: AppRoleAssignment.ReadWrite.All → same as above
if ($currentRoles -contains "AppRoleAssignment.ReadWrite.All") {
    $escalationPaths += [ordered]@{
        Path        = "AppRoleAssignment.ReadWrite.All → Grant any permission to any SP"
        Risk        = "CRITICAL"
        Description = "Direct permission grant without needing Application.ReadWrite.All"
    }
}

# Path 3: RoleManagement.ReadWrite.Directory → assign Global Admin
if ($currentRoles -contains "RoleManagement.ReadWrite.Directory") {
    $escalationPaths += [ordered]@{
        Path        = "RoleManagement.ReadWrite.Directory → Assign Global Admin role"
        Risk        = "CRITICAL"
        Description = "Can assign any directory role including Global Administrator"
    }
}

# Path 4: Directory.ReadWrite.All → create user + assign roles
if ($currentRoles -contains "Directory.ReadWrite.All") {
    $escalationPaths += [ordered]@{
        Path        = "Directory.ReadWrite.All → Create new user (confirmed Stryker TTP)"
        Risk        = "HIGH"
        Description = "Can create users. Requires separate role assignment permission to make admin."
    }
}

# Path 5: Policy.ReadWrite.ConditionalAccess → disable CA
if ($currentRoles -contains "Policy.ReadWrite.ConditionalAccess") {
    $escalationPaths += [ordered]@{
        Path        = "Policy.ReadWrite.ConditionalAccess → Disable all CA policies"
        Risk        = "CRITICAL"
        Description = "Can disable CA policies to remove MFA, device compliance, and location restrictions"
    }
}

# Path 6: Already have Intune write — no escalation needed
$hasIntuneWrite = $currentRoles | Where-Object { $_ -match "DeviceManagement.*(ReadWrite|PrivilegedOperations)" }
if ($hasIntuneWrite) {
    $escalationPaths += [ordered]@{
        Path        = "DIRECT — Already have Intune write access"
        Risk        = "CRITICAL"
        Description = "No escalation needed. Can deploy scripts, modify configs, or wipe devices now."
    }
}

Save-Json "19_escalation_paths" $escalationPaths

if ($escalationPaths.Count -gt 0) {
    Write-Alert "Escalation paths identified: $($escalationPaths.Count)"
    foreach ($path in $escalationPaths) {
        if ($path.Risk -eq "CRITICAL") {
            Write-Critical "$($path.Path)"
        }
        else {
            Write-Alert "$($path.Path)"
        }
        Write-Host "      $($path.Description)" -ForegroundColor DarkGray
    }
}
else {
    Write-Finding "No escalation paths from current permissions"
}

# ============================================================
# MODULE 8: STRYKER SCENARIO RISK ASSESSMENT
# ============================================================

Write-Phase "Module 8: Stryker Scenario Risk Assessment"

$assessment = [ordered]@{
    CompletedAt            = (Get-Date -Format "o")
    TenantName             = $tenantDisplayName
    TotalUsers             = $users.Count
    GlobalAdmins           = $globalAdmins.Count
    IntuneAdmins           = $intuneAdmins.Count
    TotalManagedDevices    = $managedDevices.Count
    DevicesSyncedRecently  = $intuneStats.RecentlySynced_24h
    MAAConfigured          = ($maaPolicies.Count -gt 0)
    WorkloadCAExists       = ($workloadPolicies.Count -gt 0)
    EscalationPathsFound   = $escalationPaths.Count
    CriticalPaths          = ($escalationPaths | Where-Object { $_.Risk -eq "CRITICAL" }).Count
    CurrentPermissions     = $currentRoles
    StrykerRiskRating      = "UNKNOWN"
    StrykerRiskFactors     = @()
    Recommendations        = @()
}

$riskFactors = @()
$riskScore = 0

# Factor 1: Blast radius
if ($managedDevices.Count -gt 10000) {
    $riskFactors += "CRITICAL: $($managedDevices.Count) managed devices — mass wipe would be catastrophic"
    $riskScore += 3
}
elseif ($managedDevices.Count -gt 1000) {
    $riskFactors += "HIGH: $($managedDevices.Count) managed devices at risk"
    $riskScore += 2
}
elseif ($managedDevices.Count -gt 0) {
    $riskFactors += "MEDIUM: $($managedDevices.Count) managed devices"
    $riskScore += 1
}

# Factor 2: MAA
if ($maaPolicies.Count -eq 0) {
    $riskFactors += "CRITICAL: No Multi-Admin Approval — single admin can mass-wipe (Stryker exact gap)"
    $riskScore += 3
}

# Factor 3: Workload identity CA
if ($workloadPolicies.Count -eq 0) {
    $riskFactors += "HIGH: No CA policies for service principals — SP auth bypasses all access controls"
    $riskScore += 2
}

# Factor 4: Escalation possible
if (($escalationPaths | Where-Object { $_.Risk -eq "CRITICAL" }).Count -gt 0) {
    $riskFactors += "CRITICAL: Escalation path to Intune admin exists from current SP permissions"
    $riskScore += 3
}

# Factor 5: Direct Intune access
if ($hasIntuneWrite) {
    $riskFactors += "CRITICAL: Current SP has DIRECT Intune write access — no escalation needed"
    $riskScore += 4
}

# Factor 6: Global admin count
if ($globalAdmins.Count -gt 5) {
    $riskFactors += "MEDIUM: $($globalAdmins.Count) Global Admins — large attack surface for credential compromise"
    $riskScore += 1
}

# Factor 7: Synced admin accounts
$syncedAdmins = @($adminMap | Where-Object {
    $_.MemberUPN -and ($users | Where-Object { $_.userPrincipalName -eq $_.MemberUPN -and $_.onPremisesSyncEnabled -eq $true })
})
if ($syncedAdmins.Count -gt 0) {
    $riskFactors += "HIGH: $($syncedAdmins.Count) admin accounts synced from on-prem AD — on-prem compromise escalates to cloud"
    $riskScore += 2
}

# Rate overall risk
$assessment.StrykerRiskRating = switch {
    ($riskScore -ge 8) { "CRITICAL" }
    ($riskScore -ge 5) { "HIGH" }
    ($riskScore -ge 3) { "MEDIUM" }
    default            { "LOW" }
}
$assessment.StrykerRiskFactors = $riskFactors

# Recommendations
$recs = @()
if ($maaPolicies.Count -eq 0) {
    $recs += "IMMEDIATE: Enable Multi-Admin Approval for wipe, retire, and delete actions in Intune"
}
if ($workloadPolicies.Count -eq 0) {
    $recs += "IMMEDIATE: Create Conditional Access policies targeting workload identities (requires Workload Identity Premium)"
}
if ($globalAdmins.Count -gt 5) {
    $recs += "HIGH: Reduce standing Global Admin assignments — use PIM with FIDO2-gated activation"
}
if ($intuneAdmins.Count -gt 3) {
    $recs += "HIGH: Reduce standing Intune Admin assignments — use PIM with approval workflow"
}
if ($hasIntuneWrite) {
    $recs += "CRITICAL: Revoke or rotate credentials for this SP immediately — it has direct Intune write access"
}
if ($escalationPaths.Count -gt 0) {
    $recs += "HIGH: Review and restrict Application.ReadWrite.All and AppRoleAssignment.ReadWrite.All grants"
}
$recs += "Ensure Intune audit logs (RemoteWipe, FactoryReset, deviceManagementScript creation) are forwarded to SIEM"
$recs += "Create threshold alert: ≥3 device wipe commands in 60 minutes → auto-lockout initiating admin"
$recs += "Restrict Intune admin access to PAWs with device compliance enforcement"
$recs += "Monitor service principal sign-in logs for anomalous source IPs"

$assessment.Recommendations = $recs
Save-Json "20_stryker_assessment" $assessment

# Final output
Write-Host ""
Write-Host "$('=' * 70)" -ForegroundColor White
Write-Host "  STRYKER SCENARIO RISK ASSESSMENT" -ForegroundColor White
Write-Host "$('=' * 70)" -ForegroundColor White
Write-Host ""

$ratingColor = switch ($assessment.StrykerRiskRating) {
    "CRITICAL" { "Red" }
    "HIGH"     { "Yellow" }
    "MEDIUM"   { "DarkYellow" }
    default    { "Green" }
}
Write-Host "  Overall Risk:   $($assessment.StrykerRiskRating)" -ForegroundColor $ratingColor
Write-Host "  Blast Radius:   $($managedDevices.Count) devices" -ForegroundColor $ratingColor
Write-Host "  MAA Configured: $(if ($assessment.MAAConfigured) {'Yes'} else {'NO — CRITICAL GAP'})" -ForegroundColor $(if ($assessment.MAAConfigured) {"Green"} else {"Red"})
Write-Host "  Workload CA:    $(if ($assessment.WorkloadCAExists) {'Yes'} else {'NO — SP bypasses all CA'})" -ForegroundColor $(if ($assessment.WorkloadCAExists) {"Green"} else {"Red"})
Write-Host "  Escalation:     $($assessment.CriticalPaths) critical paths" -ForegroundColor $(if ($assessment.CriticalPaths -gt 0) {"Red"} else {"Green"})
Write-Host ""

Write-Host "  Risk Factors:" -ForegroundColor Yellow
$riskFactors | ForEach-Object {
    $c = if ($_ -match "^CRITICAL") { "Red" } elseif ($_ -match "^HIGH") { "Yellow" } else { "DarkGray" }
    Write-Host "    → $_" -ForegroundColor $c
}

Write-Host ""
Write-Host "  Recommendations:" -ForegroundColor Cyan
$recs | ForEach-Object {
    $c = if ($_ -match "^IMMEDIATE|^CRITICAL") { "Red" } elseif ($_ -match "^HIGH") { "Yellow" } else { "DarkGray" }
    Write-Host "    → $_" -ForegroundColor $c
}

Write-Host ""
Write-Host "$('=' * 70)" -ForegroundColor White
Write-Host ""
Write-Host "[*] All output saved to: $OutputDir" -ForegroundColor Cyan
Write-Host "[*] Key files:" -ForegroundColor Cyan
Write-Host "    12_admin_roles.json         — All admin role assignments" -ForegroundColor DarkGray
Write-Host "    14_ca_analysis.json         — CA policy gap analysis" -ForegroundColor DarkGray
Write-Host "    16_intune_managed_devices   — Full device inventory (blast radius)" -ForegroundColor DarkGray
Write-Host "    18_maa_policies.json        — Multi-Admin Approval status" -ForegroundColor DarkGray
Write-Host "    19_escalation_paths.json    — Privilege escalation opportunities" -ForegroundColor DarkGray
Write-Host "    20_stryker_assessment.json  — Combined risk assessment" -ForegroundColor DarkGray
Write-Host ""
