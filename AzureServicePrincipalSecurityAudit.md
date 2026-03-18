# Azure Service Principal Security Audit Cheatsheet

> All commands run in **Azure Cloud Shell** or any terminal with `az` CLI authenticated.
> Graph API calls can also be run in [Graph Explorer](https://developer.microsoft.com/en-us/graph/graph-explorer).

-----

## 1. Authentication Methods Overview

|Method                    |Security|How It Works                                                       |
|--------------------------|--------|-------------------------------------------------------------------|
|Client Secret             |Lowest  |Password string stored in Entra, shared with the app               |
|Certificate               |Medium  |Asymmetric key pair — private key held by app, public cert in Entra|
|Federated Credential (WIF)|Highest |No stored secret — external IdP issues OIDC token, Entra trusts it |

**Goal:** Migrate from secrets → certificates → federated credentials where possible.

-----

## 2. Enumerate All Service Principals

### Full SP Inventory with Auth Methods

```bash
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/applications?\$select=displayName,appId,passwordCredentials,keyCredentials,federatedIdentityCredentials" \
  -o json
```

### Count by Auth Type (quick summary)

```bash
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/applications?\$select=displayName,passwordCredentials,keyCredentials" \
  -o json | jq '{
    total: (.value | length),
    with_secrets: [.value[] | select(.passwordCredentials | length > 0)] | length,
    with_certs: [.value[] | select(.keyCredentials | length > 0)] | length,
    no_credentials: [.value[] | select((.passwordCredentials | length == 0) and (.keyCredentials | length == 0))] | length
  }'
```

-----

## 3. Enumerate by Credential Type

### SPs with Client Secrets

```bash
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/applications?\$select=displayName,appId,passwordCredentials" \
  -o json | jq '.value[] | select(.passwordCredentials | length > 0) |
  {name: .displayName, appId: .appId, secrets: [.passwordCredentials[] | {hint: .hint, created: .startDateTime, expires: .endDateTime}]}'
```

### SPs with Certificate Credentials

```bash
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/applications?\$select=displayName,appId,keyCredentials" \
  -o json | jq '.value[] | select(.keyCredentials | length > 0) |
  {name: .displayName, appId: .appId, certs: [.keyCredentials[] | {type: .type, usage: .usage, expires: .endDateTime}]}'
```

### SPs with Federated Credentials

```bash
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/applications" \
  -o json | jq -r '.value[].id' | while read id; do
  fic=$(az rest --method GET --url "https://graph.microsoft.com/v1.0/applications/$id/federatedIdentityCredentials" 2>/dev/null)
  count=$(echo "$fic" | jq '.value | length')
  if [ "$count" -gt "0" ]; then
    name=$(az rest --method GET --url "https://graph.microsoft.com/v1.0/applications/$id" --query displayName -o tsv)
    echo "$fic" | jq --arg n "$name" '{app: $n, federated: [.value[] | {name: .name, issuer: .issuer, subject: .subject, audiences: .audiences}]}'
  fi
done
```

-----

## 4. Credential Hygiene Findings

### Expired Secrets (should be removed)

```bash
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/applications?\$select=displayName,appId,passwordCredentials" \
  -o json | jq --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '.value[] | select(.passwordCredentials[]? | .endDateTime < $now) |
  {name: .displayName, expired: [.passwordCredentials[] | select(.endDateTime < $now) | .endDateTime]}'
```

### Secrets with Long Expiry (>1 year = risk)

```bash
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/applications?\$select=displayName,passwordCredentials" \
  -o json | jq --arg cutoff "$(date -u -d '+365 days' +%Y-%m-%dT%H:%M:%SZ)" \
  '.value[] | select(.passwordCredentials[]? | .endDateTime > $cutoff) |
  {name: .displayName, longLived: [.passwordCredentials[] | select(.endDateTime > $cutoff) | .endDateTime]}'
```

### Multiple Secrets on One App (credential sprawl)

```bash
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/applications?\$select=displayName,passwordCredentials" \
  -o json | jq '.value[] | select(.passwordCredentials | length > 1) |
  {name: .displayName, secretCount: (.passwordCredentials | length)}'
```

### SPs with Both Secrets AND Certificates (inconsistent auth)

```bash
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/applications?\$select=displayName,passwordCredentials,keyCredentials" \
  -o json | jq '.value[] | select((.passwordCredentials | length > 0) and (.keyCredentials | length > 0)) |
  {name: .displayName, secrets: (.passwordCredentials | length), certs: (.keyCredentials | length)}'
```

### Expired Certificates

```bash
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/applications?\$select=displayName,appId,keyCredentials" \
  -o json | jq --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '.value[] | select(.keyCredentials[]? | .endDateTime < $now) |
  {name: .displayName, expiredCerts: [.keyCredentials[] | select(.endDateTime < $now) | .endDateTime]}'
```

-----

## 5. Permission Enumeration

### App Role Assignments (application-level permissions)

```bash
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/servicePrincipals?\$expand=appRoleAssignments" \
  -o json | jq '.value[] | select(.appRoleAssignments | length > 0) |
  {name: .displayName, appId: .appId, permissions: [.appRoleAssignments[] | .appRoleId]}'
```

### Resolve App Role IDs to Readable Names

```bash
GRAPH_SP_ID=$(az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/servicePrincipals?\$filter=appId eq '00000003-0000-0000-c000-000000000000'" \
  --query "value[0].id" -o tsv)

az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/servicePrincipals/$GRAPH_SP_ID/appRoles" \
  --query "value[].{Permission:value, Id:id, Description:description}" -o table
```

### Find SPs with Dangerous Graph Permissions

```bash
# Get Graph SP role mappings, then cross-reference
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/servicePrincipals/$GRAPH_SP_ID/appRoles" \
  -o json > /tmp/graph-roles.json

az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/servicePrincipals?\$expand=appRoleAssignments" \
  -o json | jq --slurpfile roles /tmp/graph-roles.json '
  .value[] | select(.appRoleAssignments | length > 0) |
  {name: .displayName, dangerous: [.appRoleAssignments[] |
    . as $a | $roles[0].value[] | select(.id == $a.appRoleId) |
    select(.value | test("ReadWrite|FullControl|Directory.Read")) | .value]
  } | select(.dangerous | length > 0)'
```

### OAuth2 Delegated Permissions Granted Tenant-Wide

```bash
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?\$filter=consentType eq 'AllPrincipals'" \
  --query "value[].{ClientId:clientId, Scope:scope}" -o table
```

### Azure RBAC Roles Assigned to Service Principals

```bash
az role assignment list --all \
  --query "[?principalType=='ServicePrincipal'].{SP:principalName, Role:roleDefinitionName, Scope:scope}" -o table
```

### SPs with Owner or Contributor at Subscription Level

```bash
az role assignment list --all \
  --query "[?principalType=='ServicePrincipal' && (roleDefinitionName=='Owner' || roleDefinitionName=='Contributor') && contains(scope, '/subscriptions/') && !contains(scope, '/resourceGroups/')].{SP:principalName, Role:roleDefinitionName, Scope:scope}" -o table
```

-----

## 6. Ownership & Governance

### Apps with No Owners (orphaned)

```bash
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/applications" \
  -o json | jq -r '.value[] | "\(.id) \(.displayName)"' | while read id name; do
  count=$(az rest --method GET --url "https://graph.microsoft.com/v1.0/applications/$id/owners" --query "value | length(@)" 2>/dev/null)
  if [ "$count" = "0" ]; then
    echo "Ownerless: $name ($id)"
  fi
done
```

### Apps Owned by Guest Users

```bash
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/applications" \
  -o json | jq -r '.value[].id' | while read id; do
  az rest --method GET --url "https://graph.microsoft.com/v1.0/applications/$id/owners" \
    --query "value[?userType=='Guest'].{Owner:displayName, App:'$id'}" -o tsv 2>/dev/null
done
```

### SPs Created Recently (last 30 days — potential unauthorized creation)

```bash
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/applications?\$filter=createdDateTime ge $(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)&\$select=displayName,appId,createdDateTime" \
  --query "value[].{Name:displayName, AppId:appId, Created:createdDateTime}" -o table
```

### Who Can Create App Registrations

```bash
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" \
  --query "{UsersCanRegisterApps:defaultUserRolePermissions.allowedToCreateApps}" -o json
```

-----

## 7. Consent & Exposure

### Apps with Admin-Consented Permissions

```bash
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?\$filter=consentType eq 'AllPrincipals'" \
  -o json | jq '.value[] | {clientId: .clientId, scope: .scope, consentType: .consentType}'
```

### Recent Consent Grants in Audit Logs (potential consent phishing)

```bash
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?\$filter=activityDisplayName eq 'Consent to application'&\$top=50" \
  --query "value[].{Actor:initiatedBy.user.userPrincipalName, App:targetResources[0].displayName, Date:activityDateTime}" -o table
```

### Apps Exposed to External Tenants (multi-tenant apps)

```bash
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/applications?\$filter=signInAudience eq 'AzureADMultipleOrgs' or signInAudience eq 'AzureADandPersonalMicrosoftAccount'" \
  --query "value[].{Name:displayName, Audience:signInAudience, AppId:appId}" -o table
```

-----

## 8. Audit Log — SP Activity

### SP Sign-In Activity (last 7 days)

```bash
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/auditLogs/signIns?\$filter=signInEventTypes/any(t: t eq 'servicePrincipal')&\$top=50" \
  --query "value[].{App:appDisplayName, IP:ipAddress, Status:status.errorCode, Date:createdDateTime}" -o table
```

### Risky Service Principals (Identity Protection)

```bash
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/identityProtection/riskyServicePrincipals" \
  --query "value[].{Name:displayName, RiskLevel:riskLevel, RiskState:riskState}" -o table
```

### Credential Changes in Audit Logs (secret/cert additions)

```bash
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?\$filter=activityDisplayName eq 'Update application – Certificates and secrets management'&\$top=50" \
  --query "value[].{Actor:initiatedBy.user.userPrincipalName, App:targetResources[0].displayName, Date:activityDateTime}" -o table
```

-----

## 9. Critical Permissions to Flag

|Permission                          |Risk    |Why                                                 |
|------------------------------------|--------|----------------------------------------------------|
|`RoleManagement.ReadWrite.Directory`|Critical|Can self-escalate to Global Admin                   |
|`Directory.ReadWrite.All`           |Critical|Full read/write to all directory objects            |
|`Application.ReadWrite.All`         |Critical|Can create/modify any app registration              |
|`AppRoleAssignment.ReadWrite.All`   |Critical|Can grant any permission to any SP                  |
|`Mail.ReadWrite`                    |High    |Read/send email as any user                         |
|`Files.ReadWrite.All`               |High    |Access all SharePoint/OneDrive files                |
|`User.ReadWrite.All`                |High    |Modify any user account                             |
|`Group.ReadWrite.All`               |High    |Modify group memberships including privileged groups|
|`Policy.ReadWrite.ConditionalAccess`|High    |Can disable Conditional Access policies             |
|`Sites.FullControl.All`             |High    |Full control of all SharePoint sites                |

-----

## 10. Remediation Quick Reference

|Finding                                     |Action                                               |
|--------------------------------------------|-----------------------------------------------------|
|Client secret exists                        |Migrate to cert or federated credential (WIF)        |
|Secret expiry > 1 year                      |Enforce max 90-180 day rotation policy               |
|Expired secrets still present               |Delete immediately via portal or CLI                 |
|Multiple secrets per app                    |Consolidate, remove unused                           |
|Both secrets and certs on same app          |Standardize on one method, remove the other          |
|Orphaned app (no owner)                     |Assign owner or decommission                         |
|Guest-owned app registration                |Transfer ownership to internal user                  |
|Tenant-wide admin consent                   |Scope to specific users/groups                       |
|Owner/Contributor RBAC at subscription      |Scope down to resource group level                   |
|Multi-tenant app with no business need      |Restrict to single tenant                            |
|`Users can register apps` = true            |Set to false, delegate via Application Developer role|
|SP with `RoleManagement.ReadWrite.Directory`|Remove or replace with scoped admin unit roles       |

-----

## Useful Links

- [Graph Explorer](https://developer.microsoft.com/en-us/graph/graph-explorer)
- [App Roles Reference](https://learn.microsoft.com/en-us/graph/permissions-reference)
- [Workload Identity Federation](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation)
- [Service Principal Security Best Practices](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/service-principal-security)
- [Consent & Permissions Overview](https://learn.microsoft.com/en-us/entra/identity-platform/consent-types-developer)
