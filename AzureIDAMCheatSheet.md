# Azure IDAM Security Audit Cheatsheet

> All commands run in **Azure Cloud Shell** or any terminal with `az` CLI authenticated.
> Graph API calls can also be run in [Graph Explorer](https://developer.microsoft.com/en-us/graph/graph-explorer).

-----

## 1. Quick Posture Overview

### Secure Score (single-pane across Entra + Azure + Intune + M365)

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/security/secureScores?$top=1' --query "value[0].{Score:currentScore, Max:maxScore}"
```

### Actionable Improvement Items

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/security/secureScoreControlProfiles' --query "value[].{Action:title, MaxScore:maxScore, Service:service}" -o table
```

### Entra ID Recommendations (stale accounts, MFA gaps, unused apps)

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/directory/recommendations?$filter=status eq '\''active'\''' --query "value[].{Title:displayName, Impact:impactType, Status:status}" -o table
```

### Defender for Cloud — Unhealthy Findings

```bash
az security assessment list --query "[?status.code=='Unhealthy'].{Name:displayName, Resource:resourceDetails.id}" -o table
```

-----

## 2. Privileged Roles & Admin Accounts

### List Global Admins (should be ≤ 5, ideally 2)

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/directoryRoles/filterByRoleTemplateId(roleTemplateId='\''62e90394-69f5-4237-9190-012177145e10'\'')/members' --query "value[].{Name:displayName, UPN:userPrincipalName, Type:@odata.type}" -o table
```

### List All Activated Directory Roles and Their Members

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/directoryRoles?$expand=members' --query "value[].{Role:displayName, Members:members[].displayName}" -o json
```

### Permanent (Active) Role Assignments — should be minimal

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=principal' --query "value[].{Role:roleDefinitionId, Principal:principal.displayName, Type:principal.@odata.type}" -o table
```

### PIM Eligible Assignments (preferred over permanent)

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances' --query "value[].{Principal:principalId, Role:roleDefinitionId, Start:startDateTime, End:endDateTime}" -o table
```

### Find Users with Multiple Privileged Roles (SoD violations)

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=principal' -o json | jq '[.value[] | {principal: .principal.displayName, role: .roleDefinitionId}] | group_by(.principal) | map(select(length > 1)) | .[] | {user: .[0].principal, roles: [.[].role]}'
```

-----

## 3. Conditional Access Policies

### List All Conditional Access Policies and Their State

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' --query "value[].{Name:displayName, State:state, GrantControls:grantControls.builtInControls}" -o table
```

### Find Policies That Are Disabled or Report-Only

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' --query "value[?state!='enabled'].{Name:displayName, State:state}" -o table
```

### Find Policies That Exclude Users or Groups (potential bypass)

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' --query "value[?conditions.users.excludeUsers || conditions.users.excludeGroups].{Name:displayName, ExcludedUsers:conditions.users.excludeUsers, ExcludedGroups:conditions.users.excludeGroups}" -o json
```

### Named Locations (verify trusted locations aren’t overly broad)

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations' --query "value[].{Name:displayName, Type:@odata.type, Trusted:isTrusted}" -o table
```

-----

## 4. Service Principals & App Registrations

### List All Service Principals

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/servicePrincipals?$select=displayName,appId' --query "value[].{Name:displayName, AppId:appId}" -o table
```

### Find SPs with High-Privilege App Role Assignments

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/servicePrincipals?$expand=appRoleAssignedTo' -o json | jq '.value[] | select(.appRoleAssignedTo | length > 0) | {name: .displayName, appId: .appId, roles: [.appRoleAssignedTo[].appRoleId]}'
```

### App Registrations with Key/Password Credentials

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/applications?$select=displayName,appId,passwordCredentials,keyCredentials' --query "value[?passwordCredentials || keyCredentials].{Name:displayName, AppId:appId, Secrets:passwordCredentials[].displayName, Certs:keyCredentials[].displayName}" -o json
```

### Find Apps with Expired Secrets

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/applications?$select=displayName,passwordCredentials' -o json | jq --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '.value[] | select(.passwordCredentials[]? | .endDateTime < $now) | {name: .displayName, expired: [.passwordCredentials[] | select(.endDateTime < $now) | .endDateTime]}'
```

### Apps with No Owners (orphaned)

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/applications' -o json | jq -r '.value[].id' | while read id; do
  owners=$(az rest --method GET --url "https://graph.microsoft.com/v1.0/applications/$id/owners" --query "value | length(@)")
  if [ "$owners" = "0" ]; then
    az rest --method GET --url "https://graph.microsoft.com/v1.0/applications/$id" --query "{Name:displayName, AppId:appId}" -o tsv
  fi
done
```

### OAuth2 Permission Grants (delegated permissions consented tenant-wide)

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$filter=consentType eq '\''AllPrincipals'\''' --query "value[].{ClientId:clientId, Scope:scope, ConsentType:consentType}" -o table
```

-----

## 5. Groups & Dynamic Membership

### List Privileged Groups (role-assignable groups)

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/groups?$filter=isAssignableToRole eq true' --query "value[].{Name:displayName, Id:id, MemberCount:@odata.count}" -o table
```

### Groups with No Owners

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/groups?$select=displayName,id' -o json | jq -r '.value[].id' | while read id; do
  count=$(az rest --method GET --url "https://graph.microsoft.com/v1.0/groups/$id/owners/\$count" --headers "ConsistencyLevel=eventual" 2>/dev/null || echo "0")
  if [ "$count" = "0" ]; then
    echo "Ownerless group: $id"
  fi
done
```

### Dynamic Groups — Review Membership Rules

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/groups?$filter=groupTypes/any(g:g eq '\''DynamicMembership'\'')' --query "value[].{Name:displayName, Rule:membershipRule}" -o table
```

### Nested Group Memberships in Privileged Roles

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/directoryRoles?$expand=members' -o json | jq '.value[] | {role: .displayName, groups: [.members[] | select(."@odata.type" == "#microsoft.graph.group") | .displayName]}'
```

-----

## 6. MFA & Authentication Methods

### Users Registered for MFA

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails' --query "value[].{UPN:userPrincipalName, MfaRegistered:isMfaRegistered, Methods:methodsRegistered}" -o table
```

### Users NOT Registered for MFA

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$filter=isMfaRegistered eq false' --query "value[].{UPN:userPrincipalName}" -o table
```

### Authentication Methods Policy (tenant-wide)

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy' --query "authenticationMethodConfigurations[].{Method:id, State:state}" -o table
```

### Legacy Authentication — Sign-In Logs for Basic Auth

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/auditLogs/signIns?$filter=clientAppUsed eq '\''Exchange ActiveSync'\'' or clientAppUsed eq '\''Other clients'\''&$top=50' --query "value[].{User:userDisplayName, App:clientAppUsed, Status:status.errorCode}" -o table
```

-----

## 7. Guest & External Users

### List All Guest Users

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/users?$filter=userType eq '\''Guest'\''' --query "value[].{Name:displayName, Email:mail, Created:createdDateTime}" -o table
```

### Guests with Privileged Role Assignments

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/directoryRoles?$expand=members' -o json | jq '.value[] | {role: .displayName, guests: [.members[] | select(.userType? == "Guest") | .displayName]} | select(.guests | length > 0)'
```

### External Collaboration Settings

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' --query "{GuestInviteSettings:allowInvitesFrom, GuestUserRole:guestUserRoleId}" -o json
```

### Stale Guests (no sign-in in 90+ days)

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/users?$filter=userType eq '\''Guest'\''&$select=displayName,signInActivity,createdDateTime' -o json | jq --arg cutoff "$(date -u -d '90 days ago' +%Y-%m-%dT%H:%M:%SZ)" '.value[] | select(.signInActivity.lastSignInDateTime < $cutoff or .signInActivity.lastSignInDateTime == null) | {name: .displayName, lastSignIn: .signInActivity.lastSignInDateTime}'
```

-----

## 8. Azure RBAC (Subscription & Resource Level)

### List All Role Assignments at Subscription Scope

```bash
az role assignment list --all --query "[].{Principal:principalName, Role:roleDefinitionName, Scope:scope}" -o table
```

### Find Owner/Contributor Assignments at Subscription Level

```bash
az role assignment list --all --query "[?roleDefinitionName=='Owner' || roleDefinitionName=='Contributor'].{Principal:principalName, Role:roleDefinitionName, Scope:scope}" -o table
```

### Custom Role Definitions — Review for Wildcard Actions

```bash
az role definition list --custom-role-only true --query "[].{Name:roleName, Actions:permissions[0].actions, DataActions:permissions[0].dataActions}" -o json
```

### Find Classic (Co-)Administrators — Deprecated, Remove

```bash
az role assignment list --include-classic-administrators --query "[?roleDefinitionName=='CoAdministrator' || roleDefinitionName=='ServiceAdministrator'].{Principal:principalName, Role:roleDefinitionName}" -o table
```

### Orphaned Role Assignments (principal deleted but assignment remains)

```bash
az role assignment list --all --query "[?principalName==''].{PrincipalId:principalId, Role:roleDefinitionName, Scope:scope}" -o table
```

-----

## 9. Intune / Endpoint Management

### Device Compliance Policies

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies' --query "value[].{Name:displayName, Id:id}" -o table
```

### Non-Compliant Device Summary

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicyDeviceStateSummary'
```

### Device Configuration Profiles

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations' --query "value[].{Name:displayName, Type:@odata.type}" -o table
```

### Managed Devices Not Compliant

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$filter=complianceState eq '\''noncompliant'\''' --query "value[].{Device:deviceName, User:userDisplayName, OS:operatingSystem, State:complianceState}" -o table
```

-----

## 10. Sign-In & Audit Monitoring

### Risky Users

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?$filter=riskState eq '\''atRisk'\''' --query "value[].{UPN:userPrincipalName, RiskLevel:riskLevel, RiskState:riskState, LastUpdated:riskLastUpdatedDateTime}" -o table
```

### Risky Service Principals

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/identityProtection/riskyServicePrincipals' --query "value[].{Name:displayName, RiskLevel:riskLevel, RiskState:riskState}" -o table
```

### Recent Admin Activity in Audit Logs

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$filter=activityDisplayName eq '\''Add member to role'\''&$top=20' --query "value[].{Activity:activityDisplayName, Actor:initiatedBy.user.userPrincipalName, Target:targetResources[0].displayName, Date:activityDateTime}" -o table
```

### Consent Grants in Audit Logs (potential consent phishing)

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$filter=activityDisplayName eq '\''Consent to application'\''&$top=50' --query "value[].{Actor:initiatedBy.user.userPrincipalName, App:targetResources[0].displayName, Date:activityDateTime}" -o table
```

-----

## 11. Network & Key Vault Security

### Key Vaults Without Private Endpoints

```bash
az keyvault list --query "[?properties.privateEndpointConnections==null || length(properties.privateEndpointConnections)==\`0\`].{Name:name, RG:resourceGroup}" -o table
```

### Key Vaults with Public Network Access Enabled

```bash
az keyvault list --query "[?properties.publicNetworkAccess=='Enabled'].{Name:name, RG:resourceGroup}" -o table
```

### Storage Accounts Allowing Public Blob Access

```bash
az storage account list --query "[?allowBlobPublicAccess==\`true\`].{Name:name, RG:resourceGroup}" -o table
```

### NSGs with Inbound Allow Any from Internet

```bash
az network nsg list --query "[].{NSG:name, RG:resourceGroup, Rules:securityRules[?access=='Allow' && direction=='Inbound' && sourceAddressPrefix=='*'].{Rule:name, Port:destinationPortRange}}" -o json
```

-----

## Quick Reference — Key Role Template IDs

|Role                           |roleTemplateId                        |
|-------------------------------|--------------------------------------|
|Global Administrator           |`62e90394-69f5-4237-9190-012177145e10`|
|Privileged Role Administrator  |`e8611ab8-c189-46e8-94e1-60213ab1f814`|
|Security Administrator         |`194ae4cb-b126-40b2-bd5b-6091b380977d`|
|Exchange Administrator         |`29232cdf-9323-42fd-ade2-1d097af3e4de`|
|SharePoint Administrator       |`f28a1f50-f6e7-4571-818b-6a12f2af6b6c`|
|Intune Administrator           |`3a2c62db-5318-420d-8d74-23affee5d9d5`|
|Application Administrator      |`9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3`|
|Cloud Application Administrator|`158c047a-c907-4556-b7ef-446551a6b5f7`|

-----

## Useful Links

- [Graph Explorer](https://developer.microsoft.com/en-us/graph/graph-explorer) — Run any Graph query in browser
- [Defender for Cloud CLI Reference](https://learn.microsoft.com/en-us/cli/azure/security/assessment)
- [Entra Recommendations API](https://learn.microsoft.com/en-us/graph/api/directory-list-recommendations)
- [Secure Score API](https://learn.microsoft.com/en-us/graph/api/security-list-securescores)
- [PIM API Reference](https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleeligibilityscheduleinstances)
- [Conditional Access API](https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-list-policies)
- [CIS Microsoft Azure Foundations Benchmark](https://www.cisecurity.org/benchmark/azure)
