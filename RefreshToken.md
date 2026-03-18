Cloud Shell and az CLI don’t expose refresh tokens directly — they’re stored internally by MSAL and not surfaced via az account get-access-token.
Where az CLI stores tokens

# Token cache location (MSAL)
cat ~/.azure/msal_token_cache.json | jq '.RefreshToken'


This file contains the cached refresh tokens. In Cloud Shell, this path exists for your session.
Extract a refresh token via device code flow
If the MSAL cache is empty or you need a fresh one:

# Get your tenant ID
TENANT=$(az account show --query tenantId -o tsv)

# Initiate device code flow (uses Azure CLI client ID)
curl -s -X POST "https://login.microsoftonline.com/$TENANT/oauth2/v2.0/devicecode" -d "client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&scope=https://graph.microsoft.com/.default offline_access" | jq


Follow the device code prompt, then exchange:

# After authenticating, exchange for tokens
curl -s -X POST "https://login.microsoftonline.com/$TENANT/oauth2/v2.0/token" -d "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&device_code=<DEVICE_CODE_FROM_ABOVE>" | jq '{access_token: .access_token[:50], refresh_token: .refresh_token[:50], expires_in: .expires_in}'


Why this matters for auditing
Refresh tokens are the persistence mechanism. Key things to check in your environment:
	∙	Token lifetime policies — Are refresh tokens set to expire?
	∙	Continuous Access Evaluation (CAE) — Is it enabled to revoke tokens in near-real-time?
	∙	Revocation capability — Can you revoke refresh tokens for compromised users?

# Check token lifetime policies
az rest --method GET --url 'https://graph.microsoft.com/v1.0/policies/tokenLifetimePolicies' -o json

# Revoke all refresh tokens for a specific user (incident response)
az rest --method POST --url 'https://graph.microsoft.com/v1.0/users/<USER_ID>/revokeSignInSessions'


The 04b07795-8ddb-461a-bbee-02f9e1bf7b46 client ID above is the well-known Azure CLI first-party app — it’s the same one az login uses.​​​​​​​​​​​​​​​​
