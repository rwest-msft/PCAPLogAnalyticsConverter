import logging
from scapy.all import rdpcap, Packet
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.layers.dns import DNS
import json
import requests
import os
import tempfile
import hashlib
import hmac
import base64
import datetime
from typing import List, Dict, Any
import time

import azure.functions as func

app = func.FunctionApp()

@app.blob_trigger(arg_name="myblob", 
                  path="pcap-files/{name}",
                  connection="AzureWebJobsStorage")
def pcap_processor(myblob: func.InputStream) -> None:
    """
    Azure Function to process PCAP files from blob storage and send data to Log Analytics.
    Triggered when a new PCAP file is uploaded to the 'pcap-files' container.
    """
    try:
        logging.info(f"Processing PCAP blob: {myblob.name}, Size: {myblob.length} bytes")
        
        # Validate file size (limit to 100MB for performance)
        max_size = 100 * 1024 * 1024  # 100MB
        if myblob.length > max_size:
            logging.error(f"File too large: {myblob.length} bytes. Maximum allowed: {max_size} bytes")
            return
        
        # Process PCAP file
        packet_data = process_pcap_file(myblob)
        
        if not packet_data:
            logging.warning("No packet data extracted from PCAP file")
            return
        
        # Send data to Log Analytics with retry logic
        success = send_to_log_analytics(packet_data, myblob.name)
        
        if success:
            logging.info(f"Successfully processed {len(packet_data)} packets from {myblob.name}")
        else:
            logging.error(f"Failed to send data to Log Analytics for {myblob.name}")
            
    except Exception as e:
        logging.error(f"Error processing PCAP file {myblob.name}: {str(e)}")
        raise

def process_pcap_file(blob_stream: func.InputStream) -> List[Dict[str, Any]]:
    """
    Process PCAP file and extract packet information.
    
    Args:
        blob_stream: Azure Function InputStream containing PCAP data
        
    Returns:
        List of packet dictionaries
    """
    packet_data = []
    temp_file = None
    
    try:        # Create temporary file to store blob content
        # scapy rdpcap requires a file path, not a stream
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as temp_file:
            temp_file.write(blob_stream.read())
            temp_file_path = temp_file.name
        
        logging.info(f"Created temporary file: {temp_file_path}")
          # Process PCAP file with scapy
        packets = rdpcap(temp_file_path)
        
        for i, packet in enumerate(packets):
            try:
                # Extract key packet information
                packet_info = {
                    "timestamp": str(packet.time),
                    "length": len(packet),
                    "packet_number": i + 1,
                    "layers": [layer.__class__.__name__ for layer in packet.layers()]
                }
                
                # Add Ethernet layer information if present
                if packet.haslayer(Ether):
                    eth = packet[Ether]
                    packet_info.update({
                        "eth_src": eth.src,
                        "eth_dst": eth.dst,
                        "eth_type": eth.type
                    })
                
                # Add IP layer information if present
                if packet.haslayer(IP):
                    ip = packet[IP]
                    packet_info.update({
                        "source": ip.src,
                        "destination": ip.dst,
                        "ip_version": ip.version,
                        "ttl": ip.ttl,
                        "protocol_number": ip.proto,
                        "ip_len": ip.len
                    })
                    
                    # Set protocol name based on IP protocol
                    if ip.proto == 1:
                        packet_info["protocol"] = "ICMP"
                    elif ip.proto == 6:
                        packet_info["protocol"] = "TCP"
                    elif ip.proto == 17:
                        packet_info["protocol"] = "UDP"
                    else:
                        packet_info["protocol"] = f"IP_PROTO_{ip.proto}"
                else:
                    packet_info.update({
                        "source": "N/A",
                        "destination": "N/A",
                        "protocol": "Non-IP"
                    })
                
                # Add TCP layer information if present
                if packet.haslayer(TCP):
                    tcp = packet[TCP]
                    packet_info.update({
                        "src_port": tcp.sport,
                        "dst_port": tcp.dport,
                        "tcp_flags": tcp.flags
                    })
                
                # Add UDP layer information if present
                elif packet.haslayer(UDP):
                    udp = packet[UDP]
                    packet_info.update({
                        "src_port": udp.sport,
                        "dst_port": udp.dport
                    })
                
                # Add ICMP layer information if present
                if packet.haslayer(ICMP):
                    icmp = packet[ICMP]
                    packet_info.update({
                        "icmp_type": icmp.type,
                        "icmp_code": icmp.code
                    })
                
                # Add DNS layer information if present
                if packet.haslayer(DNS):
                    dns = packet[DNS]
                    packet_info.update({
                        "dns_id": dns.id,
                        "dns_qr": dns.qr,
                        "dns_opcode": dns.opcode,
                        "dns_rcode": dns.rcode
                    })
                    
                    # Add query information if present
                    if dns.qd:
                        packet_info["dns_query"] = dns.qd.qname.decode('utf-8', errors='ignore')
                
                # Add packet summary for better readability
                packet_info["summary"] = packet.summary()
                
                packet_data.append(packet_info)
                  # Limit packets to prevent memory issues
                if len(packet_data) >= 10000:
                    logging.warning("Reached packet limit (10,000). Processing partial file.")
                    break
                    
            except Exception as e:
                logging.warning(f"Error processing packet {i}: {str(e)}")
                continue
        
        logging.info(f"Extracted {len(packet_data)} packets from PCAP file")
        
    except Exception as e:
        logging.error(f"Error processing PCAP file: {str(e)}")
        raise
    finally:
        # Clean up temporary file
        if temp_file and os.path.exists(temp_file_path):
            os.unlink(temp_file_path)
            logging.info("Temporary file cleaned up")
    
    return packet_data

def send_to_log_analytics(data: List[Dict[str, Any]], source_file: str) -> bool:
    """
    Send packet data to Azure Log Analytics workspace.
    
    Args:
        data: List of packet dictionaries
        source_file: Name of the source PCAP file
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Get configuration from environment variables
        workspace_id = os.getenv("LOG_ANALYTICS_WORKSPACE_ID")
        shared_key = os.getenv("LOG_ANALYTICS_SHARED_KEY")
        
        if not workspace_id or not shared_key:
            logging.error("Log Analytics workspace ID or shared key not configured")
            return False
        
        log_type = "PCAPData"
        
        # Add metadata to each record
        enriched_data = []
        for packet in data:
            enriched_packet = packet.copy()
            enriched_packet.update({
                "source_file": source_file,
                "ingestion_time": datetime.datetime.utcnow().isoformat(),
                "function_version": "1.0"
            })
            enriched_data.append(enriched_packet)
        
        # Send data with retry logic
        return send_to_log_analytics_with_retry(enriched_data, workspace_id, shared_key, log_type)
        
    except Exception as e:
        logging.error(f"Error sending data to Log Analytics: {str(e)}")
        return False

def send_to_log_analytics_with_retry(data: List[Dict], workspace_id: str, 
                                   shared_key: str, log_type: str, max_retries: int = 3) -> bool:
    """
    Send data to Log Analytics with exponential backoff retry logic.
    
    Args:
        data: Data to send
        workspace_id: Log Analytics workspace ID
        shared_key: Log Analytics shared key
        log_type: Custom log type name
        max_retries: Maximum number of retry attempts
        
    Returns:
        True if successful, False otherwise
    """
    for attempt in range(max_retries):
        try:
            body = json.dumps(data, default=str)
            headers = build_signature(workspace_id, shared_key, body, log_type)
            
            url = f'https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01'
            
            response = requests.post(url, headers=headers, data=body, timeout=30)
            
            if response.status_code == 200:
                logging.info(f"Successfully sent {len(data)} records to Log Analytics")
                return True
            else:
                logging.warning(f"Log Analytics returned status code: {response.status_code}, Response: {response.text}")
                
        except requests.exceptions.RequestException as e:
            logging.warning(f"Attempt {attempt + 1} failed: {str(e)}")
            
        if attempt < max_retries - 1:
            # Exponential backoff
            wait_time = 2 ** attempt
            logging.info(f"Retrying in {wait_time} seconds...")
            time.sleep(wait_time)
    
    logging.error(f"Failed to send data to Log Analytics after {max_retries} attempts")
    return False

def build_signature(workspace_id: str, shared_key: str, body: str, log_type: str) -> Dict[str, str]:
    """
    Build the authorization signature for Log Analytics Data Collector API.
    
    Args:
        workspace_id: Log Analytics workspace ID
        shared_key: Log Analytics shared key
        body: Request body
        log_type: Custom log type
        
    Returns:
        Dictionary containing HTTP headers
    """
    x_ms_date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    
    string_to_hash = f"POST\n{content_length}\napplication/json\nx-ms-date:{x_ms_date}\n/api/logs"
    bytes_to_hash = bytes(string_to_hash, 'UTF-8')
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    
    authorization = f"SharedKey {workspace_id}:{encoded_hash}"
    
    return {
        'Content-Type': 'application/json',
        'Authorization': authorization,
        'Log-Type': log_type,
        'x-ms-date': x_ms_date
    }

@app.function_name(name="test_config")
@app.route(route="test", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def test_config(req: func.HttpRequest) -> func.HttpResponse:
    """Test function to check environment variables and configuration"""
    try:
        logging.info('Test configuration function called')
        
        # Check environment variables
        workspace_id = os.environ.get('LOG_ANALYTICS_WORKSPACE_ID', 'NOT_SET')
        shared_key = os.environ.get('LOG_ANALYTICS_SHARED_KEY', 'NOT_SET')
        
        result = {
            'workspace_id': workspace_id[:8] + '...' if workspace_id != 'NOT_SET' else 'NOT_SET',
            'shared_key_status': 'SET' if shared_key != 'NOT_SET' else 'NOT_SET',
            'shared_key_length': len(shared_key) if shared_key != 'NOT_SET' else 0,
            'key_vault_reference': shared_key.startswith('@Microsoft.KeyVault') if shared_key != 'NOT_SET' else False
        }
        
        return func.HttpResponse(
            json.dumps(result, indent=2),
            status_code=200,
            mimetype="application/json"
        )
    except Exception as e:
        logging.error(f"Error in test function: {str(e)}")
        return func.HttpResponse(
            f"Error: {str(e)}",
            status_code=500
        )


