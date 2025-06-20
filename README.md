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

### Option 1: Azure CLI
```bash
# Deploy function code
func azure functionapp publish your-function-app-name --python

# Set application settings
az functionapp config appsettings set \
  --name your-function-app-name \
  --resource-group your-resource-group \
  --settings LOG_ANALYTICS_WORKSPACE_ID=your-workspace-id
```

### Option 2: VS Code Azure Functions Extension
1. Install Azure Functions extension
2. Sign in to Azure
3. Deploy to Function App

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
