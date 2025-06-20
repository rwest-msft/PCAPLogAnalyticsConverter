# Guide: Setting up Development Storage for Azure Functions

## Option 1: Azurite (Recommended)

### Install Azurite
```powershell
# Install Node.js first if you don't have it
# Download from: https://nodejs.org/

# Install Azurite globally
npm install -g azurite
```

### Start Azurite
```powershell
# Create directory for Azurite data
mkdir C:\azurite

# Start Azurite
azurite --silent --location C:\azurite --debug C:\azurite\debug.log
```

### VS Code Integration (Easier)
1. Install the "Azurite" extension in VS Code
2. Press Ctrl+Shift+P and run "Azurite: Start"
3. Azurite will start automatically

### Your current local.settings.json is correct:
```json
"AzureWebJobsStorage": "UseDevelopmentStorage=true"
```

## Option 2: Use Real Azure Storage Account

If you prefer to use a real storage account (like in your other project):

```json
{
  "IsEncrypted": false,
  "Values": {
    "AzureWebJobsStorage": "DefaultEndpointsProtocol=https;AccountName=yourstorageaccount;AccountKey=yourkey;EndpointSuffix=core.windows.net",
    "FUNCTIONS_WORKER_RUNTIME": "python",
    "LOG_ANALYTICS_WORKSPACE_ID": "21217efb-8500-4acf-b807-f80496bb022f",
    "LOG_ANALYTICS_SHARED_KEY": "hCDl9BDEnZYSWzVdq4jzaG205sYZWfm27hYEnudD5WIcxYdGbrrqM5OIQFXr5Pbtd0xBgL/+l1rdugzAVoZVbA=="
  }
}
```

## Creating pcap-files Container

### With Azurite:
```powershell
# Install Azure Storage Explorer or use Azure CLI
az storage container create --name pcap-files --connection-string "UseDevelopmentStorage=true"
```

### With Real Storage Account:
```powershell
az storage container create --name pcap-files --account-name yourstorageaccount --account-key yourkey
```

## Testing Your Setup

1. Start Azurite (if using local emulation)
2. Create the "pcap-files" container
3. Upload a test PCAP file
4. Run your function locally: `func start`

## Troubleshooting

### If you get connection errors:
- Make sure Azurite is running
- Check Windows Firewall settings
- Verify the port 10000 (blob), 10001 (queue), 10002 (table) are available

### Alternative: Docker approach
```powershell
# Run Azurite in Docker
docker run -p 10000:10000 -p 10001:10001 -p 10002:10002 mcr.microsoft.com/azure-storage/azurite
```
