# Azurite Storage Management Script for PCAP Function

# Full Azurite connection string (this is what works with Azure CLI)
$AZURITE_CONNECTION_STRING = "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;"

# Create the pcap-files container
Write-Host "Creating pcap-files container..." -ForegroundColor Green
az storage container create --name pcap-files --connection-string $AZURITE_CONNECTION_STRING

# List all containers to verify
Write-Host "`nListing containers:" -ForegroundColor Green
az storage container list --connection-string $AZURITE_CONNECTION_STRING --output table

# Upload a test file (if you have one)
# Uncomment and modify the path below if you want to test with a real PCAP file
# Write-Host "`nUploading test PCAP file..." -ForegroundColor Green
# az storage blob upload --file "path\to\your\test.pcap" --container-name pcap-files --name "test.pcap" --connection-string $AZURITE_CONNECTION_STRING

Write-Host "`nContainer setup complete!" -ForegroundColor Green
Write-Host "You can now:" -ForegroundColor Yellow
Write-Host "1. Upload PCAP files to the 'pcap-files' container" -ForegroundColor Yellow
Write-Host "2. Run your function locally with: func start" -ForegroundColor Yellow
Write-Host "3. Monitor function logs for processing results" -ForegroundColor Yellow
