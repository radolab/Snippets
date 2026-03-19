<#
.SYNOPSIS
    Azure Security Enumeration & Misconfiguration Scanner
.DESCRIPTION
    Enumerates Azure resources and identifies critical security misconfigurations.
    Designed to run under a Service Principal context.
.NOTES
    Requires: Az PowerShell module, Microsoft.Graph (optional for deeper Entra checks)
    Permissions needed: Reader on subscriptions, Directory.Read.All for Entra ID
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\AzSecurityReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').json",
    [switch]$ExportCSV
)

#region ============ HELPERS ============
function Write-Finding {
    param(
        [string]$Category,
        [string]$Severity,   # CRITICAL, HIGH, MEDIUM, LOW, INFO
        [string]$Resource,
        [string]$Finding,
        [string]$Recommendation
    )
    $color = switch ($Severity) {
        "CRITICAL" { "Red" }
        "HIGH"     { "DarkRed" }
        "MEDIUM"   { "Yellow" }
        "LOW"      { "Cyan" }
        default    { "Gray" }
    }
    Write-Host "[$Severity] " -ForegroundColor $color -NoNewline
    Write-Host "$Category | $Resource | $Finding"
    
    return [PSCustomObject]@{
        Category       = $Category
        Severity       = $Severity
        Resource       = $Resource
        Finding        = $Finding
        Recommendation = $Recommendation
        Timestamp      = (Get-Date -Format "o")
    }
}

$findings = [System.Collections.ArrayList]::new()
#endregion

#region ============ CONTEXT VALIDATION ============
Write-Host "`n========================================" -ForegroundColor Green
Write-Host " Azure Security Enumeration Scanner" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Green

$context = Get-AzContext
if (-not $context) {
    Write-Error "Not logged in. Run Connect-AzAccount first."
    exit 1
}

Write-Host "Account:      $($context.Account.Id)" -ForegroundColor Cyan
Write-Host "Tenant:       $($context.Tenant.Id)" -ForegroundColor Cyan
Write-Host "Subscription: $($context.Subscription.Name) ($($context.Subscription.Id))" -ForegroundColor Cyan
Write-Host ""

$subscriptions = Get-AzSubscription -TenantId $context.Tenant.Id | Where-Object { $_.State -eq "Enabled" }
Write-Host "Accessible subscriptions: $($subscriptions.Count)" -ForegroundColor Cyan
#endregion

#region ============ 1. SERVICE PRINCIPALS & APP REGISTRATIONS ============
Write-Host "`n--- [1/10] Service Principals & App Credentials ---" -ForegroundColor Magenta

try {
    # Get all app registrations with credentials
    $apps = Get-AzADApplication -First 1000

    foreach ($app in $apps) {
        # Check password credentials (client secrets)
        $passwordCreds = $app.PasswordCredential
        foreach ($cred in $passwordCreds) {
            $daysUntilExpiry = ($cred.EndDateTime - (Get-Date)).Days
            $totalLifespan = ($cred.EndDateTime - $cred.StartDateTime).Days

            # Secret expiring soon
            if ($daysUntilExpiry -le 30 -and $daysUntilExpiry -gt 0) {
                $null = $findings.Add((Write-Finding -Category "AppCredentials" -Severity "HIGH" `
                    -Resource "App: $($app.DisplayName) (AppId: $($app.AppId))" `
                    -Finding "Client secret expires in $daysUntilExpiry days (KeyId: $($cred.KeyId))" `
                    -Recommendation "Rotate the secret or migrate to managed identity / workload identity federation."))
            }
            # Expired secret still present
            elseif ($daysUntilExpiry -le 0) {
                $null = $findings.Add((Write-Finding -Category "AppCredentials" -Severity "MEDIUM" `
                    -Resource "App: $($app.DisplayName) (AppId: $($app.AppId))" `
                    -Finding "Expired client secret still present (expired $([Math]::Abs($daysUntilExpiry)) days ago)" `
                    -Recommendation "Remove expired credentials to reduce attack surface."))
            }
            # Long-lived secret (>1 year)
            if ($totalLifespan -gt 365) {
                $null = $findings.Add((Write-Finding -Category "AppCredentials" -Severity "HIGH" `
                    -Resource "App: $($app.DisplayName) (AppId: $($app.AppId))" `
                    -Finding "Client secret has $totalLifespan-day lifespan (max recommended: 365 days)" `
                    -Recommendation "Use short-lived secrets (90-180 days) or migrate to certificate/workload identity federation."))
            }
            # Very long-lived (>2 years)
            if ($totalLifespan -gt 730) {
                $null = $findings.Add((Write-Finding -Category "AppCredentials" -Severity "CRITICAL" `
                    -Resource "App: $($app.DisplayName) (AppId: $($app.AppId))" `
                    -Finding "Client secret has $totalLifespan-day lifespan (>2 years) — excessive" `
                    -Recommendation "Immediately rotate. Use workload identity federation (OIDC) or certificates."))
            }
        }

        # Check certificate credentials
        $keyCreds = $app.KeyCredential
        foreach ($cred in $keyCreds) {
            $daysUntilExpiry = ($cred.EndDateTime - (Get-Date)).Days
            if ($daysUntilExpiry -le 30 -and $daysUntilExpiry -gt 0) {
                $null = $findings.Add((Write-Finding -Category "AppCredentials" -Severity "HIGH" `
                    -Resource "App: $($app.DisplayName) (AppId: $($app.AppId))" `
                    -Finding "Certificate expires in $daysUntilExpiry days" `
                    -Recommendation "Rotate certificate before expiry."))
            }
        }

        # Multiple secrets on same app
        if ($passwordCreds.Count -gt 2) {
            $null = $findings.Add((Write-Finding -Category "AppCredentials" -Severity "MEDIUM" `
                -Resource "App: $($app.DisplayName) (AppId: $($app.AppId))" `
                -Finding "$($passwordCreds.Count) client secrets configured — indicates poor credential hygiene" `
                -Recommendation "Consolidate to a single active credential. Remove unused secrets."))
        }
    }
    Write-Host "  Scanned $($apps.Count) app registrations." -ForegroundColor DarkGray
}
catch {
    Write-Warning "App registration enumeration failed: $($_.Exception.Message)"
}
#endregion

#region ============ 2. PRIVILEGED ROLE ASSIGNMENTS ============
Write-Host "`n--- [2/10] Privileged RBAC Role Assignments ---" -ForegroundColor Magenta

$dangerousRoles = @("Owner", "Contributor", "User Access Administrator")

foreach ($sub in $subscriptions) {
    Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue | Out-Null
    try {
        $roleAssignments = Get-AzRoleAssignment -Scope "/subscriptions/$($sub.Id)"

        foreach ($ra in $roleAssignments) {
            # Subscription-level Owner/Contributor/UAA
            if ($ra.Scope -eq "/subscriptions/$($sub.Id)" -and $ra.RoleDefinitionName -in $dangerousRoles) {
                $severity = if ($ra.RoleDefinitionName -eq "Owner") { "CRITICAL" } else { "HIGH" }
                $null = $findings.Add((Write-Finding -Category "RBAC" -Severity $severity `
                    -Resource "Sub: $($sub.Name) | $($ra.DisplayName) ($($ra.ObjectType))" `
                    -Finding "'$($ra.RoleDefinitionName)' assigned at subscription scope" `
                    -Recommendation "Scope to resource group. Use PIM for JIT elevation if permanent."))
            }

            # Root management group assignments
            if ($ra.Scope -eq "/") {
                $null = $findings.Add((Write-Finding -Category "RBAC" -Severity "CRITICAL" `
                    -Resource "$($ra.DisplayName) ($($ra.ObjectType))" `
                    -Finding "'$($ra.RoleDefinitionName)' at root management group scope" `
                    -Recommendation "Remove root-level assignments. Assign at lowest necessary scope."))
            }

            # Service principals with Owner
            if ($ra.ObjectType -eq "ServicePrincipal" -and $ra.RoleDefinitionName -eq "Owner") {
                $null = $findings.Add((Write-Finding -Category "RBAC" -Severity "CRITICAL" `
                    -Resource "SP: $($ra.DisplayName) on $($ra.Scope)" `
                    -Finding "Service Principal has Owner role" `
                    -Recommendation "Reduce to Contributor or a custom role with only required permissions."))
            }

            # Deprecated classic roles
            if ($ra.RoleDefinitionName -match "^(CoAdministrator|AccountAdministrator|ServiceAdministrator)$") {
                $null = $findings.Add((Write-Finding -Category "RBAC" -Severity "HIGH" `
                    -Resource "$($ra.DisplayName)" `
                    -Finding "Classic admin role '$($ra.RoleDefinitionName)' still in use" `
                    -Recommendation "Migrate to Azure RBAC roles. Classic roles are deprecated."))
            }
        }
        Write-Host "  Sub '$($sub.Name)': $($roleAssignments.Count) role assignments scanned." -ForegroundColor DarkGray
    }
    catch {
        Write-Warning "RBAC enumeration failed for $($sub.Name): $($_.Exception.Message)"
    }
}
#endregion

#region ============ 3. STORAGE ACCOUNTS ============
Write-Host "`n--- [3/10] Storage Accounts ---" -ForegroundColor Magenta

foreach ($sub in $subscriptions) {
    Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue | Out-Null
    try {
        $storageAccounts = Get-AzStorageAccount

        foreach ($sa in $storageAccounts) {
            # Public blob access enabled
            if ($sa.AllowBlobPublicAccess -eq $true) {
                $null = $findings.Add((Write-Finding -Category "Storage" -Severity "CRITICAL" `
                    -Resource "Storage: $($sa.StorageAccountName) ($($sa.ResourceGroupName))" `
                    -Finding "Public blob access is ENABLED" `
                    -Recommendation "Set AllowBlobPublicAccess to false unless explicitly required."))
            }

            # HTTPS only not enforced
            if ($sa.EnableHttpsTrafficOnly -eq $false) {
                $null = $findings.Add((Write-Finding -Category "Storage" -Severity "HIGH" `
                    -Resource "Storage: $($sa.StorageAccountName)" `
                    -Finding "HTTPS-only traffic is NOT enforced (HTTP allowed)" `
                    -Recommendation "Enable 'Secure transfer required' (EnableHttpsTrafficOnly)."))
            }

            # Minimum TLS version
            if ($sa.MinimumTlsVersion -ne "TLS1_2") {
                $null = $findings.Add((Write-Finding -Category "Storage" -Severity "HIGH" `
                    -Resource "Storage: $($sa.StorageAccountName)" `
                    -Finding "Minimum TLS version is '$($sa.MinimumTlsVersion)' (should be TLS1_2)" `
                    -Recommendation "Set MinimumTlsVersion to TLS1_2."))
            }

            # Shared key access enabled (prefer Entra auth)
            if ($sa.AllowSharedKeyAccess -ne $false) {
                $null = $findings.Add((Write-Finding -Category "Storage" -Severity "MEDIUM" `
                    -Resource "Storage: $($sa.StorageAccountName)" `
                    -Finding "Shared key access is enabled (storage account keys)" `
                    -Recommendation "Disable shared key access; use Entra ID (Azure AD) authentication via RBAC."))
            }

            # Network rules — check if default action is Allow
            $netRules = $sa.NetworkRuleSet
            if ($netRules -and $netRules.DefaultAction -eq "Allow") {
                $null = $findings.Add((Write-Finding -Category "Storage" -Severity "HIGH" `
                    -Resource "Storage: $($sa.StorageAccountName)" `
                    -Finding "Network default action is 'Allow' (open to all networks)" `
                    -Recommendation "Set default action to 'Deny' and add VNet/IP rules or use private endpoints."))
            }

            # Infrastructure encryption
            if (-not $sa.EnableInfrastructureEncryption) {
                $null = $findings.Add((Write-Finding -Category "Storage" -Severity "LOW" `
                    -Resource "Storage: $($sa.StorageAccountName)" `
                    -Finding "Infrastructure (double) encryption not enabled" `
                    -Recommendation "Enable for data at rest protection with two layers of encryption."))
            }
        }
    }
    catch {
        Write-Warning "Storage enumeration failed for $($sub.Name): $($_.Exception.Message)"
    }
}
#endregion

#region ============ 4. KEY VAULTS ============
Write-Host "`n--- [4/10] Key Vaults ---" -ForegroundColor Magenta

foreach ($sub in $subscriptions) {
    Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue | Out-Null
    try {
        $vaults = Get-AzKeyVault

        foreach ($vaultInfo in $vaults) {
            $vault = Get-AzKeyVault -VaultName $vaultInfo.VaultName -ResourceGroupName $vaultInfo.ResourceGroupName

            # Soft delete not enabled (should be default now, but check)
            if (-not $vault.EnableSoftDelete) {
                $null = $findings.Add((Write-Finding -Category "KeyVault" -Severity "HIGH" `
                    -Resource "KV: $($vault.VaultName)" `
                    -Finding "Soft delete is NOT enabled" `
                    -Recommendation "Enable soft delete to protect against accidental or malicious deletion."))
            }

            # Purge protection not enabled
            if (-not $vault.EnablePurgeProtection) {
                $null = $findings.Add((Write-Finding -Category "KeyVault" -Severity "HIGH" `
                    -Resource "KV: $($vault.VaultName)" `
                    -Finding "Purge protection is NOT enabled" `
                    -Recommendation "Enable purge protection to prevent permanent deletion during retention period."))
            }

            # Public network access
            if ($vault.PublicNetworkAccess -ne "Disabled") {
                $null = $findings.Add((Write-Finding -Category "KeyVault" -Severity "MEDIUM" `
                    -Resource "KV: $($vault.VaultName)" `
                    -Finding "Public network access is enabled" `
                    -Recommendation "Disable public access; use private endpoints for Key Vault access."))
            }

            # RBAC vs access policies
            if (-not $vault.EnableRbacAuthorization) {
                $null = $findings.Add((Write-Finding -Category "KeyVault" -Severity "MEDIUM" `
                    -Resource "KV: $($vault.VaultName)" `
                    -Finding "Using legacy access policies instead of RBAC authorization" `
                    -Recommendation "Migrate to RBAC authorization for centralized, granular access control."))
            }
        }
    }
    catch {
        Write-Warning "Key Vault enumeration failed for $($sub.Name): $($_.Exception.Message)"
    }
}
#endregion

#region ============ 5. NETWORK SECURITY GROUPS ============
Write-Host "`n--- [5/10] Network Security Groups ---" -ForegroundColor Magenta

$dangerousPorts = @(22, 3389, 445, 1433, 3306, 5432, 27017, 9200)
$dangerousPortNames = @{
    22 = "SSH"; 3389 = "RDP"; 445 = "SMB"; 1433 = "MSSQL";
    3306 = "MySQL"; 5432 = "PostgreSQL"; 27017 = "MongoDB"; 9200 = "Elasticsearch"
}

foreach ($sub in $subscriptions) {
    Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue | Out-Null
    try {
        $nsgs = Get-AzNetworkSecurityGroup

        foreach ($nsg in $nsgs) {
            foreach ($rule in $nsg.SecurityRules) {
                if ($rule.Direction -eq "Inbound" -and $rule.Access -eq "Allow") {
                    $isOpenToInternet = ($rule.SourceAddressPrefix -in @("*", "0.0.0.0/0", "Internet", "Any"))

                    if ($isOpenToInternet) {
                        # Any/any inbound rule
                        if ($rule.DestinationPortRange -eq "*") {
                            $null = $findings.Add((Write-Finding -Category "NSG" -Severity "CRITICAL" `
                                -Resource "NSG: $($nsg.Name) | Rule: $($rule.Name)" `
                                -Finding "All ports open to the internet (0.0.0.0/0 → *)" `
                                -Recommendation "Remove or restrict to specific source IPs and ports."))
                        }
                        else {
                            # Check specific dangerous ports
                            foreach ($port in $dangerousPorts) {
                                $portStr = $port.ToString()
                                $portRanges = @($rule.DestinationPortRange) + @($rule.DestinationPortRanges | Where-Object { $_ })
                                
                                foreach ($pr in $portRanges) {
                                    $isMatch = $false
                                    if ($pr -eq $portStr -or $pr -eq "*") { $isMatch = $true }
                                    elseif ($pr -match "^(\d+)-(\d+)$") {
                                        if ($port -ge [int]$Matches[1] -and $port -le [int]$Matches[2]) { $isMatch = $true }
                                    }
                                    if ($isMatch) {
                                        $svcName = $dangerousPortNames[$port]
                                        $null = $findings.Add((Write-Finding -Category "NSG" -Severity "CRITICAL" `
                                            -Resource "NSG: $($nsg.Name) | Rule: $($rule.Name)" `
                                            -Finding "Port $port ($svcName) open to the internet" `
                                            -Recommendation "Restrict source to specific IPs or use Azure Bastion / JIT VM access."))
                                        break
                                    }
                                }
                            }
                        }
                    }
                }
            }

            # NSG not associated with any subnet or NIC
            if (-not $nsg.Subnets -and -not $nsg.NetworkInterfaces) {
                $null = $findings.Add((Write-Finding -Category "NSG" -Severity "LOW" `
                    -Resource "NSG: $($nsg.Name)" `
                    -Finding "NSG is not associated with any subnet or NIC (orphaned)" `
                    -Recommendation "Remove unused NSGs or associate them with target subnets/NICs."))
            }
        }
    }
    catch {
        Write-Warning "NSG enumeration failed for $($sub.Name): $($_.Exception.Message)"
    }
}
#endregion

#region ============ 6. VIRTUAL MACHINES ============
Write-Host "`n--- [6/10] Virtual Machines ---" -ForegroundColor Magenta

foreach ($sub in $subscriptions) {
    Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue | Out-Null
    try {
        $vms = Get-AzVM -Status

        foreach ($vm in $vms) {
            # Public IP directly on VM
            $nicIds = $vm.NetworkProfile.NetworkInterfaces.Id
            foreach ($nicId in $nicIds) {
                $nic = Get-AzNetworkInterface -ResourceId $nicId -ErrorAction SilentlyContinue
                foreach ($ipConfig in $nic.IpConfigurations) {
                    if ($ipConfig.PublicIpAddress) {
                        $pip = Get-AzPublicIpAddress -ResourceGroupName $vm.ResourceGroupName -ErrorAction SilentlyContinue |
                            Where-Object { $_.Id -eq $ipConfig.PublicIpAddress.Id }
                        if ($pip) {
                            $null = $findings.Add((Write-Finding -Category "VM" -Severity "HIGH" `
                                -Resource "VM: $($vm.Name) ($($vm.ResourceGroupName))" `
                                -Finding "VM has public IP: $($pip.IpAddress)" `
                                -Recommendation "Remove public IP. Use Azure Bastion, VPN, or JIT VM Access instead."))
                        }
                    }
                }
            }

            # No managed identity
            if (-not $vm.Identity) {
                $null = $findings.Add((Write-Finding -Category "VM" -Severity "MEDIUM" `
                    -Resource "VM: $($vm.Name)" `
                    -Finding "No managed identity assigned" `
                    -Recommendation "Assign system or user-assigned managed identity for keyless authentication."))
            }

            # Disk encryption check
            $disks = Get-AzDisk -ResourceGroupName $vm.ResourceGroupName | 
                Where-Object { $_.ManagedBy -eq $vm.Id }
            foreach ($disk in $disks) {
                if ($disk.EncryptionSettingsCollection.Enabled -ne $true -and -not $disk.Encryption.DiskEncryptionSetId) {
                    # Platform-managed keys are default, but check for explicit encryption
                    if ($disk.Encryption.Type -eq "EncryptionAtRestWithPlatformKey") {
                        $null = $findings.Add((Write-Finding -Category "VM" -Severity "LOW" `
                            -Resource "VM: $($vm.Name) | Disk: $($disk.Name)" `
                            -Finding "Disk uses platform-managed keys only (no CMK)" `
                            -Recommendation "Consider customer-managed keys (CMK) for regulatory compliance."))
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "VM enumeration failed for $($sub.Name): $($_.Exception.Message)"
    }
}
#endregion

#region ============ 7. SQL & DATABASE SECURITY ============
Write-Host "`n--- [7/10] SQL Servers & Databases ---" -ForegroundColor Magenta

foreach ($sub in $subscriptions) {
    Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue | Out-Null
    try {
        $sqlServers = Get-AzSqlServer -ErrorAction SilentlyContinue

        foreach ($server in $sqlServers) {
            # Entra-only authentication check
            if (-not $server.Administrators.AzureADOnlyAuthentication) {
                $null = $findings.Add((Write-Finding -Category "SQL" -Severity "HIGH" `
                    -Resource "SQL: $($server.ServerName)" `
                    -Finding "SQL authentication enabled (not Entra-only)" `
                    -Recommendation "Enable Azure AD-only authentication to eliminate SQL password-based auth."))
            }

            # Public network access
            if ($server.PublicNetworkAccess -ne "Disabled") {
                $null = $findings.Add((Write-Finding -Category "SQL" -Severity "HIGH" `
                    -Resource "SQL: $($server.ServerName)" `
                    -Finding "Public network access is enabled" `
                    -Recommendation "Disable public access; use private endpoints."))
            }

            # Minimum TLS
            if ($server.MinimalTlsVersion -ne "1.2") {
                $null = $findings.Add((Write-Finding -Category "SQL" -Severity "HIGH" `
                    -Resource "SQL: $($server.ServerName)" `
                    -Finding "Minimum TLS version is '$($server.MinimalTlsVersion)'" `
                    -Recommendation "Set minimum TLS version to 1.2."))
            }

            # Auditing
            $auditing = Get-AzSqlServerAudit -ServerName $server.ServerName -ResourceGroupName $server.ResourceGroupName -ErrorAction SilentlyContinue
            if (-not $auditing -or $auditing.BlobStorageTargetState -ne "Enabled") {
                $null = $findings.Add((Write-Finding -Category "SQL" -Severity "MEDIUM" `
                    -Resource "SQL: $($server.ServerName)" `
                    -Finding "Server auditing may not be fully configured" `
                    -Recommendation "Enable auditing to Log Analytics or Storage for compliance."))
            }

            # Firewall rules — check for 0.0.0.0 (Allow Azure services) or wide ranges
            $fwRules = Get-AzSqlServerFirewallRule -ServerName $server.ServerName -ResourceGroupName $server.ResourceGroupName -ErrorAction SilentlyContinue
            foreach ($rule in $fwRules) {
                if ($rule.StartIpAddress -eq "0.0.0.0" -and $rule.EndIpAddress -eq "0.0.0.0") {
                    $null = $findings.Add((Write-Finding -Category "SQL" -Severity "MEDIUM" `
                        -Resource "SQL: $($server.ServerName) | Rule: $($rule.FirewallRuleName)" `
                        -Finding "'Allow Azure services' firewall rule enabled (0.0.0.0)" `
                        -Recommendation "Remove and use private endpoints or specific VNet rules instead."))
                }
                elseif ($rule.StartIpAddress -eq "0.0.0.0" -and $rule.EndIpAddress -eq "255.255.255.255") {
                    $null = $findings.Add((Write-Finding -Category "SQL" -Severity "CRITICAL" `
                        -Resource "SQL: $($server.ServerName) | Rule: $($rule.FirewallRuleName)" `
                        -Finding "Firewall rule allows ALL IP addresses (0.0.0.0 - 255.255.255.255)" `
                        -Recommendation "Remove immediately. Restrict to specific IPs or use private endpoints."))
                }
            }
        }
    }
    catch {
        Write-Warning "SQL enumeration failed for $($sub.Name): $($_.Exception.Message)"
    }
}
#endregion

#region ============ 8. MICROSOFT DEFENDER FOR CLOUD ============
Write-Host "`n--- [8/10] Defender for Cloud ---" -ForegroundColor Magenta

foreach ($sub in $subscriptions) {
    Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue | Out-Null
    try {
        $pricings = Get-AzSecurityPricing -ErrorAction SilentlyContinue

        foreach ($pricing in $pricings) {
            if ($pricing.PricingTier -eq "Free") {
                $severity = if ($pricing.Name -in @("VirtualMachines", "SqlServers", "StorageAccounts", "KeyVaults")) { "HIGH" } else { "MEDIUM" }
                $null = $findings.Add((Write-Finding -Category "Defender" -Severity $severity `
                    -Resource "Sub: $($sub.Name) | Plan: $($pricing.Name)" `
                    -Finding "Defender plan '$($pricing.Name)' is on Free tier (no threat protection)" `
                    -Recommendation "Enable Standard/P2 tier for threat detection and vulnerability assessments."))
            }
        }
    }
    catch {
        Write-Warning "Defender check failed for $($sub.Name): $($_.Exception.Message)"
    }
}
#endregion

#region ============ 9. DIAGNOSTIC SETTINGS (LOGGING) ============
Write-Host "`n--- [9/10] Activity Log & Diagnostic Settings ---" -ForegroundColor Magenta

foreach ($sub in $subscriptions) {
    Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue | Out-Null
    try {
        $diagSettings = Get-AzSubscriptionDiagnosticSetting -ErrorAction SilentlyContinue

        if (-not $diagSettings -or $diagSettings.Count -eq 0) {
            $null = $findings.Add((Write-Finding -Category "Logging" -Severity "HIGH" `
                -Resource "Sub: $($sub.Name)" `
                -Finding "No diagnostic settings configured for subscription Activity Log" `
                -Recommendation "Configure Activity Log export to Log Analytics workspace or Storage Account."))
        }
    }
    catch {
        Write-Warning "Diagnostic settings check failed for $($sub.Name): $($_.Exception.Message)"
    }
}
#endregion

#region ============ 10. ENTRA ID CHECKS (via Graph REST) ============
Write-Host "`n--- [10/10] Entra ID Security Checks ---" -ForegroundColor Magenta

try {
    $token = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token
    $headers = @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" }

    # Guest users
    $guestsUri = "https://graph.microsoft.com/v1.0/users?\`$filter=userType eq 'Guest'&\`$count=true&\`$top=999"
    $guestResponse = Invoke-RestMethod -Uri $guestsUri -Headers ($headers + @{ "ConsistencyLevel" = "eventual" }) -Method GET -ErrorAction SilentlyContinue
    $guestCount = ($guestResponse.value | Measure-Object).Count
    if ($guestCount -gt 0) {
        $null = $findings.Add((Write-Finding -Category "EntraID" -Severity "INFO" `
            -Resource "Tenant" `
            -Finding "$guestCount guest user(s) found in the directory" `
            -Recommendation "Review guest accounts regularly. Ensure access reviews are configured."))
        
        # Check for guests with no recent sign-in (stale)
        foreach ($guest in $guestResponse.value) {
            if ($guest.signInActivity.lastSignInDateTime) {
                $lastSign = [datetime]$guest.signInActivity.lastSignInDateTime
                $daysSince = ((Get-Date) - $lastSign).Days
                if ($daysSince -gt 90) {
                    $null = $findings.Add((Write-Finding -Category "EntraID" -Severity "MEDIUM" `
                        -Resource "Guest: $($guest.displayName) ($($guest.userPrincipalName))" `
                        -Finding "Guest user has not signed in for $daysSince days" `
                        -Recommendation "Remove stale guest accounts or disable access."))
                }
            }
        }
    }

    # Privileged directory roles with permanent assignments
    $directoryRoles = @(
        @{ Id = "62e90394-69f5-4237-9190-012177145e10"; Name = "Global Administrator" },
        @{ Id = "e8611ab8-c189-46e8-94e1-60213ab1f814"; Name = "Privileged Role Administrator" },
        @{ Id = "194ae4cb-b126-40b2-bd5b-6091b380977d"; Name = "Security Administrator" },
        @{ Id = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"; Name = "Application Administrator" },
        @{ Id = "158c047a-c907-4556-b7ef-446551a6b5f7"; Name = "Cloud Application Administrator" }
    )

    foreach ($role in $directoryRoles) {
        try {
            $membersUri = "https://graph.microsoft.com/v1.0/directoryRoles(roleTemplateId='$($role.Id)')/members"
            $members = Invoke-RestMethod -Uri $membersUri -Headers $headers -Method GET -ErrorAction SilentlyContinue
            
            $memberCount = ($members.value | Measure-Object).Count
            if ($role.Name -eq "Global Administrator" -and $memberCount -gt 5) {
                $null = $findings.Add((Write-Finding -Category "EntraID" -Severity "CRITICAL" `
                    -Resource "Role: $($role.Name)" `
                    -Finding "$memberCount Global Administrators found (recommended: <=5, ideally 2-3)" `
                    -Recommendation "Reduce Global Admin count. Use least-privilege roles and PIM."))
            }

            # Check for service principals in privileged roles
            foreach ($member in $members.value) {
                if ($member.'@odata.type' -eq '#microsoft.graph.servicePrincipal') {
                    $null = $findings.Add((Write-Finding -Category "EntraID" -Severity "HIGH" `
                        -Resource "SP: $($member.displayName) in role '$($role.Name)'" `
                        -Finding "Service Principal has privileged directory role" `
                        -Recommendation "Use application permissions (API permissions) instead of directory roles where possible."))
                }
            }
        }
        catch {
            # Role may not be activated in tenant
        }
    }

    # Conditional Access policies — basic check
    try {
        $caPolicies = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -Headers $headers -Method GET -ErrorAction Stop
        $enabledPolicies = $caPolicies.value | Where-Object { $_.state -eq "enabled" }
        
        if ($enabledPolicies.Count -eq 0) {
            $null = $findings.Add((Write-Finding -Category "ConditionalAccess" -Severity "CRITICAL" `
                -Resource "Tenant" `
                -Finding "No enabled Conditional Access policies found" `
                -Recommendation "Implement baseline CA policies: require MFA, block legacy auth, device compliance."))
        }
        else {
            Write-Host "  $($enabledPolicies.Count) enabled Conditional Access policies found." -ForegroundColor DarkGray

            # Check for MFA policy
            $mfaPolicy = $enabledPolicies | Where-Object {
                $_.grantControls.builtInControls -contains "mfa"
            }
            if (-not $mfaPolicy) {
                $null = $findings.Add((Write-Finding -Category "ConditionalAccess" -Severity "CRITICAL" `
                    -Resource "Tenant" `
                    -Finding "No Conditional Access policy requiring MFA detected" `
                    -Recommendation "Create a CA policy requiring MFA for all users (minimum: all admins)."))
            }

            # Check for legacy auth blocking
            $legacyBlock = $enabledPolicies | Where-Object {
                $_.conditions.clientAppTypes -contains "exchangeActiveSync" -or 
                $_.conditions.clientAppTypes -contains "other"
            }
            if (-not $legacyBlock) {
                $null = $findings.Add((Write-Finding -Category "ConditionalAccess" -Severity "HIGH" `
                    -Resource "Tenant" `
                    -Finding "No Conditional Access policy blocking legacy authentication detected" `
                    -Recommendation "Block legacy auth protocols (ActiveSync, POP, IMAP, etc.) via CA policy."))
            }
        }
    }
    catch {
        Write-Warning "Conditional Access check requires Policy.Read.All permission: $($_.Exception.Message)"
    }
}
catch {
    Write-Warning "Entra ID checks require Graph API access: $($_.Exception.Message)"
}
#endregion

#region ============ REPORT ============
Write-Host "`n========================================" -ForegroundColor Green
Write-Host " SCAN COMPLETE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

$critCount = ($findings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
$highCount = ($findings | Where-Object { $_.Severity -eq "HIGH" }).Count
$medCount  = ($findings | Where-Object { $_.Severity -eq "MEDIUM" }).Count
$lowCount  = ($findings | Where-Object { $_.Severity -eq "LOW" }).Count
$infoCount = ($findings | Where-Object { $_.Severity -eq "INFO" }).Count

Write-Host "`nTotal findings: $($findings.Count)" -ForegroundColor White
Write-Host "  CRITICAL : $critCount" -ForegroundColor Red
Write-Host "  HIGH     : $highCount" -ForegroundColor DarkRed
Write-Host "  MEDIUM   : $medCount" -ForegroundColor Yellow
Write-Host "  LOW      : $lowCount" -ForegroundColor Cyan
Write-Host "  INFO     : $infoCount" -ForegroundColor Gray

# Export JSON
$report = @{
    ScanDate       = (Get-Date -Format "o")
    TenantId       = $context.Tenant.Id
    AccountUsed    = $context.Account.Id
    Subscriptions  = $subscriptions | Select-Object Name, Id
    Summary        = @{
        Total    = $findings.Count
        Critical = $critCount
        High     = $highCount
        Medium   = $medCount
        Low      = $lowCount
        Info     = $infoCount
    }
    Findings       = $findings
}

$report | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
Write-Host "`nReport saved to: $OutputPath" -ForegroundColor Green

# Optional CSV export
if ($ExportCSV) {
    $csvPath = $OutputPath -replace '\.json$', '.csv'
    $findings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "CSV export saved to: $csvPath" -ForegroundColor Green
}

Write-Host "`nDone.`n"
#endregion
