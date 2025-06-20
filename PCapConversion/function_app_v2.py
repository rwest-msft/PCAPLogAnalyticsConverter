import logging
import pyshark
import json
import os
import tempfile
import datetime
from typing import List, Dict, Any

import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.monitor.ingestion import LogsIngestionClient

app = func.FunctionApp()

@app.blob_trigger(arg_name="myblob", 
                  path="pcap-files/{name}",
                  connection="AzureWebJobsStorage")
def pcap_processor_v2(myblob: func.InputStream) -> None:
    """
    Enhanced Azure Function to process PCAP files using Azure Monitor Ingestion client.
    Uses Managed Identity for secure authentication.
    """
    try:
        logging.info(f"Processing PCAP blob: {myblob.name}, Size: {myblob.length} bytes")
        
        # Validate file size (limit to 100MB for performance)
        max_size = 100 * 1024 * 1024  # 100MB
        if myblob.length > max_size:
            logging.error(f"File too large: {myblob.length} bytes. Maximum allowed: {max_size} bytes")
            return
        
        # Process PCAP file
        packet_data = process_pcap_file_v2(myblob)
        
        if not packet_data:
            logging.warning("No packet data extracted from PCAP file")
            return
        
        # Send data to Log Analytics using modern client
        success = send_to_log_analytics_v2(packet_data, myblob.name)
        
        if success:
            logging.info(f"Successfully processed {len(packet_data)} packets from {myblob.name}")
        else:
            logging.error(f"Failed to send data to Log Analytics for {myblob.name}")
            
    except Exception as e:
        logging.error(f"Error processing PCAP file {myblob.name}: {str(e)}")
        raise

def process_pcap_file_v2(blob_stream: func.InputStream) -> List[Dict[str, Any]]:
    """
    Enhanced PCAP processing with better error handling and performance.
    """
    packet_data = []
    temp_file_path = None
    
    try:
        # Create temporary file for pyshark processing
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as temp_file:
            # Read blob data in chunks to handle large files efficiently
            chunk_size = 8192
            blob_data = blob_stream.read()
            temp_file.write(blob_data)
            temp_file_path = temp_file.name
        
        logging.info(f"Created temporary file: {temp_file_path}")
        
        # Process PCAP with optimized settings
        cap = pyshark.FileCapture(
            temp_file_path,
            keep_packets=False,  # Don't keep packets in memory
            use_json=True,
            include_raw=False    # Don't include raw packet data
        )
        
        packet_count = 0
        for packet in cap:
            try:
                # Extract essential packet information
                packet_info = extract_packet_info(packet, packet_count + 1)
                packet_data.append(packet_info)
                packet_count += 1
                
                # Limit packets for memory management
                if packet_count >= 10000:
                    logging.warning("Reached packet limit (10,000). Processing partial file.")
                    break
                    
            except Exception as e:
                logging.warning(f"Error processing packet {packet_count}: {str(e)}")
                continue
        
        cap.close()
        logging.info(f"Extracted {len(packet_data)} packets from PCAP file")
        
    except Exception as e:
        logging.error(f"Error processing PCAP file: {str(e)}")
        raise
    finally:
        # Cleanup
        if temp_file_path and os.path.exists(temp_file_path):
            os.unlink(temp_file_path)
    
    return packet_data

def extract_packet_info(packet, packet_number: int) -> Dict[str, Any]:
    """
    Extract structured information from a packet.
    """
    packet_info = {
        "TimeGenerated": datetime.datetime.utcnow().isoformat() + "Z",
        "PacketNumber": packet_number,
        "Length": int(packet.length) if hasattr(packet, 'length') else 0,
        "HighestLayer": packet.highest_layer if hasattr(packet, 'highest_layer') else "Unknown",
        "Layers": [layer.layer_name for layer in packet.layers] if hasattr(packet, 'layers') else []
    }
    
    # Add timestamp if available
    if hasattr(packet, 'sniff_time'):
        packet_info["PacketTimestamp"] = packet.sniff_time.isoformat()
    
    # Extract IP information
    if hasattr(packet, 'ip'):
        packet_info.update({
            "SourceIP": packet.ip.src,
            "DestinationIP": packet.ip.dst,
            "IPVersion": packet.ip.version,
            "TTL": int(packet.ip.ttl),
            "Protocol": packet.ip.proto
        })
    
    # Extract transport layer information
    if hasattr(packet, 'tcp'):
        packet_info.update({
            "SourcePort": int(packet.tcp.srcport),
            "DestinationPort": int(packet.tcp.dstport),
            "TCPFlags": packet.tcp.flags,
            "TransportProtocol": "TCP"
        })
    elif hasattr(packet, 'udp'):
        packet_info.update({
            "SourcePort": int(packet.udp.srcport),
            "DestinationPort": int(packet.udp.dstport),
            "TransportProtocol": "UDP"
        })
    
    # Extract application layer information
    if hasattr(packet, 'http'):
        packet_info["ApplicationProtocol"] = "HTTP"
        if hasattr(packet.http, 'request_method'):
            packet_info["HTTPMethod"] = packet.http.request_method
        if hasattr(packet.http, 'host'):
            packet_info["HTTPHost"] = packet.http.host
    elif hasattr(packet, 'dns'):
        packet_info["ApplicationProtocol"] = "DNS"
        if hasattr(packet.dns, 'qry_name'):
            packet_info["DNSQuery"] = packet.dns.qry_name
    
    return packet_info

def send_to_log_analytics_v2(data: List[Dict[str, Any]], source_file: str) -> bool:
    """
    Send data to Log Analytics using Azure Monitor Ingestion client with Managed Identity.
    """
    try:
        # Get configuration
        data_collection_endpoint = os.getenv("DATA_COLLECTION_ENDPOINT")
        data_collection_rule_id = os.getenv("DATA_COLLECTION_RULE_ID")
        stream_name = os.getenv("STREAM_NAME", "Custom-PCAPData_CL")
        
        if not data_collection_endpoint or not data_collection_rule_id:
            logging.error("Data Collection Endpoint or Rule ID not configured")
            return False
        
        # Initialize client with Managed Identity
        credential = DefaultAzureCredential()
        client = LogsIngestionClient(
            endpoint=data_collection_endpoint,
            credential=credential
        )
        
        # Enrich data with metadata
        enriched_data = []
        for packet in data:
            enriched_packet = packet.copy()
            enriched_packet.update({
                "SourceFile": source_file,
                "IngestionTime": datetime.datetime.utcnow().isoformat() + "Z",
                "FunctionVersion": "2.0"
            })
            enriched_data.append(enriched_packet)
        
        # Send data in batches to handle large datasets
        batch_size = 1000
        total_batches = (len(enriched_data) + batch_size - 1) // batch_size
        
        for i in range(0, len(enriched_data), batch_size):
            batch = enriched_data[i:i + batch_size]
            batch_number = (i // batch_size) + 1
            
            try:
                response = client.upload(
                    rule_id=data_collection_rule_id,
                    stream_name=stream_name,
                    logs=batch
                )
                logging.info(f"Successfully sent batch {batch_number}/{total_batches} ({len(batch)} records)")
                
            except Exception as e:
                logging.error(f"Failed to send batch {batch_number}: {str(e)}")
                return False
        
        logging.info(f"Successfully sent all {len(enriched_data)} records to Log Analytics")
        return True
        
    except Exception as e:
        logging.error(f"Error sending data to Log Analytics: {str(e)}")
        return False
