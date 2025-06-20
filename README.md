# PCAP to Log Analytics Azure Function

## Overview
This Azure Function processes PCAP (packet capture) files from Azure Blob Storage and sends the extracted packet data to Azure Log Analytics workspace for analysis and monitoring.

## Features
- **Secure Processing**: Handles PCAP files up to 100MB with proper error handling
- **Modern Authentication**: Uses Managed Identity for secure Azure service authentication
- **Batch Processing**: Efficiently processes large datasets in batches
- **Comprehensive Logging**: Detailed logging for monitoring and troubleshooting
- **Performance Optimized**: Memory-efficient packet processing with configurable limits

## Architecture
```
Blob Storage (PCAP files) → Azure Function → Log Analytics Workspace
```

## Prerequisites
1. Azure Subscription
2. Azure Function App (Python 3.9+)
3. Azure Storage Account with blob container named `pcap-files`
4. Azure Log Analytics Workspace
5. Data Collection Endpoint and Rule (for v2 implementation)

## Setup Instructions

### 1. Function App Configuration
Set the following application settings in your Function App:

#### For Version 1 (Direct API approach):
```
LOG_ANALYTICS_WORKSPACE_ID=your-workspace-id
LOG_ANALYTICS_SHARED_KEY=your-primary-or-secondary-key
AzureWebJobsStorage=your-storage-connection-string
```

#### For Version 2 (Modern approach with Managed Identity):
```
DATA_COLLECTION_ENDPOINT=https://your-endpoint.ingest.monitor.azure.com
DATA_COLLECTION_RULE_ID=dcr-xxxxxxxxxxxxxxxx
STREAM_NAME=Custom-PCAPData_CL
AzureWebJobsStorage=your-storage-connection-string
```

### 2. Managed Identity Setup (Version 2)
1. Enable System Managed Identity on your Function App
2. Assign the following roles to the Managed Identity:
   - `Monitoring Metrics Publisher` on the Data Collection Rule
   - `Storage Blob Data Reader` on the Storage Account

### 3. Data Collection Rule Setup (Version 2)
Create a Data Collection Rule with:
- Data source: Custom logs
- Destination: Your Log Analytics workspace
- Stream name: `Custom-PCAPData_CL`

### 4. Storage Container
Create a blob container named `pcap-files` in your storage account.

## Deployment

### Deploy with Azure CLI (Full Infrastructure & Function)

```bash
# 1. Log in to Azure
az login

# 2. Set variables (customize for your environment)
RESOURCE_GROUP=rg-pcap-analytics-dev
LOCATION="East US"
ENV_NAME=pcap-analytics-dev
DEPLOY_DIR=PCapConversion/infra
LOG_ANALYTICS_WORKSPACE_ID=<your-log-analytics-workspace-id>
LOG_ANALYTICS_SHARED_KEY=<your-log-analytics-shared-key>

# 3. Create the resource group
az group create --name $RESOURCE_GROUP --location "$LOCATION"

# 4. Deploy infrastructure (Bicep)
az deployment group create \
  --resource-group $RESOURCE_GROUP \
  --template-file $DEPLOY_DIR/main.bicep \
  --parameters environmentName=$ENV_NAME \
               location="$LOCATION" \
               logAnalyticsWorkspaceId=$LOG_ANALYTICS_WORKSPACE_ID \
               logAnalyticsSharedKey=$LOG_ANALYTICS_SHARED_KEY

# 5. Get output values (Function App and Key Vault names)
az deployment group show --resource-group $RESOURCE_GROUP --name $(az deployment group list --resource-group $RESOURCE_GROUP --query '[0].name' -o tsv) --query "properties.outputs"

# 6. Publish the function code
func azure functionapp publish <function-app-name-from-output> --python

# 7. Set app settings with Key Vault reference for the shared key
az functionapp config appsettings set \
  --name <function-app-name-from-output> \
  --resource-group $RESOURCE_GROUP \
  --settings \
    LOG_ANALYTICS_WORKSPACE_ID=$LOG_ANALYTICS_WORKSPACE_ID \
    LOG_ANALYTICS_SHARED_KEY=@Microsoft.KeyVault(VaultName=<key-vault-name-from-output>;SecretName=log-analytics-shared-key)
```

> **Notes:**
> - Replace `<your-log-analytics-workspace-id>` and `<your-log-analytics-shared-key>` with your actual values.
> - After deployment, use the output from step 5 to get the Function App and Key Vault names for steps 6 and 7.
> - The Bicep template automatically grants the Function App's managed identity access to Key Vault.

## Usage
1. Upload PCAP files to the `pcap-files` container in your storage account
2. The function will automatically trigger and process the files
3. Packet data will appear in your Log Analytics workspace under the `PCAPData_CL` table

## Data Schema
The function extracts the following packet information:
- Timestamp and packet number
- Source and destination IP addresses
- Protocol information (TCP/UDP/etc.)
- Port numbers
- Application layer protocols (HTTP, DNS, etc.)
- Packet length and flags

## Monitoring
- Monitor function execution in Azure Portal
- Check Application Insights for detailed telemetry
- Query processed data in Log Analytics using KQL

## Sample KQL Queries
```kusto
// Count packets by protocol
PCAPData_CL
| summarize count() by HighestLayer_s

// Top source IPs
PCAPData_CL
| where isnotempty(SourceIP_s)
| summarize count() by SourceIP_s
| top 10 by count_

// HTTP traffic analysis
PCAPData_CL
| where ApplicationProtocol_s == "HTTP"
| project TimeGenerated, SourceIP_s, DestinationIP_s, HTTPMethod_s, HTTPHost_s
```

## Troubleshooting
1. **Import errors**: Ensure all packages are installed via requirements.txt
2. **Authentication errors**: Verify Managed Identity roles and permissions
3. **File processing errors**: Check PCAP file format and size limits
4. **Log Analytics errors**: Verify workspace ID and data collection rule configuration

## Security Considerations
- Uses Managed Identity for authentication (no stored secrets)
- Temporary files are automatically cleaned up
- Connection strings should be stored securely
- Consider using Key Vault for sensitive configuration

## Performance Tuning
- Adjust packet limit (default: 10,000) based on requirements
- Increase function timeout for large files
- Consider using Premium hosting plan for better performance
- Monitor memory usage and adjust accordingly

## Secure Handling of Log Analytics Shared Key

This solution follows Azure best practices for secret management by never storing sensitive values in code or configuration files. Instead, the Log Analytics shared key is securely injected and referenced using Azure Key Vault and Bicep:

### 1. Key Provided as Deployment Parameter

- During deployment, the Log Analytics shared key is provided as a secure parameter (see `deploy.parameters.json` or your deployment pipeline).
- Example:
  ```json
  "logAnalyticsSharedKey": {
    "value": "<your-log-analytics-shared-key>"
  }
  ```

### 2. Key Vault Secret Creation via Bicep

- The Bicep template provisions an Azure Key Vault.
- The shared key is written into Key Vault as a secret named `log-analytics-shared-key`:
  ```bicep
  resource logAnalyticsKeySecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
    name: 'log-analytics-shared-key'
    parent: keyVault
    properties: {
      value: logAnalyticsSharedKey
      contentType: 'text/plain'
    }
  }
  ```

### 3. Function App References Secret via Key Vault Reference

- The Function App is configured with an app setting:
  ```
  LOG_ANALYTICS_SHARED_KEY = @Microsoft.KeyVault(VaultName=<key-vault-name>;SecretName=log-analytics-shared-key)
  ```
- This is set in the Bicep template, so the Function App reads the key securely at runtime.

### 4. Managed Identity Access

- The Function App’s managed identity is granted the `Key Vault Secrets User` role, allowing it to read secrets from Key Vault without storing credentials.

### 5. Best Practices

- **Never commit secrets**: No keys or secrets are present in code or configuration files under version control.
- **Use Key Vault for all secrets**: Store all sensitive values in Key Vault and reference them via app settings.
- **Parameterize deployments**: Always provide secrets as secure parameters during deployment, not in source files.
- **Review access**: Ensure only necessary identities have access to Key Vault secrets.

---
