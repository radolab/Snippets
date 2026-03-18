# Azure Token & ROADtools Quick Reference

## Token Generation (Cloud Shell)

```bash
# Microsoft Graph (Entra ID, M365, Intune)
az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv

# Azure Resource Manager (subscriptions, resources, RBAC)
az account get-access-token --resource https://management.azure.com --query accessToken -o tsv

# Legacy Azure AD Graph (ROADtools, older tools)
az account get-access-token --resource https://graph.windows.net --query accessToken -o tsv

# Key Vault data plane
az account get-access-token --resource https://vault.azure.net --query accessToken -o tsv

# Storage data plane
az account get-access-token --resource https://storage.azure.com --query accessToken -o tsv

# Default (no flags) = ARM token
az account get-access-token
```

## Check Current Identity

```bash
az account show --query "{Name:name, User:user.name, Type:user.type}" -o table
```

## Decode Token Payload

```bash
TOKEN=$(az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv)
echo $TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null | jq
```

## MSI Audience Error Fix

```bash
# Re-login as user (bypasses managed identity)
az login
az account get-access-token --resource https://graph.microsoft.com
```

## ROADtools

```bash
# Install
pip install roadlib roadrecon

# Gather with legacy Azure AD Graph token (most compatible)
roadrecon gather --access-token $(az account get-access-token --resource https://graph.windows.net --query accessToken -o tsv)

# Gather with Microsoft Graph (newer ROADtools versions)
roadrecon gather --access-token $(az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv) --graph

# Launch web UI to explore results
roadrecon gui
```

## Token Audiences Quick Reference

|Resource                      |Audience               |Use Case                      |
|------------------------------|-----------------------|------------------------------|
|`https://graph.microsoft.com` |Microsoft Graph        |Entra ID, M365, Intune, Teams |
|`https://management.azure.com`|ARM                    |Subscriptions, resources, RBAC|
|`https://graph.windows.net`   |Azure AD Graph (legacy)|ROADtools, older scripts      |
|`https://vault.azure.net`     |Key Vault              |Secrets, keys, certificates   |
|`https://storage.azure.com`   |Storage                |Blob, queue, table data plane |
|`https://database.windows.net`|Azure SQL              |SQL database connections      |
