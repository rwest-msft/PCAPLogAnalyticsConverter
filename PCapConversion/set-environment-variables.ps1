# Azure CLI commands to set environment variables for your Function App

# Replace these values with your actual information
$FUNCTION_APP_NAME = "your-function-app-name"
$RESOURCE_GROUP = "your-resource-group-name"

# For Version 1 (Direct API approach)
az functionapp config appsettings set `
  --name $FUNCTION_APP_NAME `
  --resource-group $RESOURCE_GROUP `
  --settings `
    "LOG_ANALYTICS_WORKSPACE_ID=your-actual-workspace-id" `
    "LOG_ANALYTICS_SHARED_KEY=your-actual-shared-key"

# For Version 2 (Modern approach with Managed Identity)
az functionapp config appsettings set `
  --name $FUNCTION_APP_NAME `
  --resource-group $RESOURCE_GROUP `
  --settings `
    "DATA_COLLECTION_ENDPOINT=https://your-endpoint.ingest.monitor.azure.com" `
    "DATA_COLLECTION_RULE_ID=dcr-xxxxxxxxxxxxxxxx" `
    "STREAM_NAME=Custom-PCAPData_CL"

# To verify the settings were applied
az functionapp config appsettings list `
  --name $FUNCTION_APP_NAME `
  --resource-group $RESOURCE_GROUP `
  --query "[?name=='LOG_ANALYTICS_WORKSPACE_ID' || name=='DATA_COLLECTION_ENDPOINT']"
