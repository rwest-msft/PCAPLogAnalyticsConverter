# Using Azure Key Vault for secure environment variable management

# 1. Create Key Vault (if you don't have one)
$KEY_VAULT_NAME = "your-keyvault-name"
$RESOURCE_GROUP = "your-resource-group-name"

az keyvault create `
  --name $KEY_VAULT_NAME `
  --resource-group $RESOURCE_GROUP `
  --location "East US"

# 2. Store secrets in Key Vault
az keyvault secret set `
  --vault-name $KEY_VAULT_NAME `
  --name "LogAnalyticsWorkspaceId" `
  --value "your-actual-workspace-id"

az keyvault secret set `
  --vault-name $KEY_VAULT_NAME `
  --name "LogAnalyticsSharedKey" `
  --value "your-actual-shared-key"

# 3. Grant Function App access to Key Vault
$FUNCTION_APP_NAME = "your-function-app-name"

# Enable System Managed Identity for Function App
az functionapp identity assign `
  --name $FUNCTION_APP_NAME `
  --resource-group $RESOURCE_GROUP

# Get the principal ID
$PRINCIPAL_ID = az functionapp identity show `
  --name $FUNCTION_APP_NAME `
  --resource-group $RESOURCE_GROUP `
  --query principalId --output tsv

# Grant Key Vault access
az keyvault set-policy `
  --name $KEY_VAULT_NAME `
  --object-id $PRINCIPAL_ID `
  --secret-permissions get

# 4. Reference Key Vault secrets in Function App settings
az functionapp config appsettings set `
  --name $FUNCTION_APP_NAME `
  --resource-group $RESOURCE_GROUP `
  --settings `
    "LOG_ANALYTICS_WORKSPACE_ID=@Microsoft.KeyVault(VaultName=$KEY_VAULT_NAME;SecretName=LogAnalyticsWorkspaceId)" `
    "LOG_ANALYTICS_SHARED_KEY=@Microsoft.KeyVault(VaultName=$KEY_VAULT_NAME;SecretName=LogAnalyticsSharedKey)"
