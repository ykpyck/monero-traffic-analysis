#!/usr/bin/env python3
import sys
import socket
import struct
import json
import datetime
import os

def uint32_to_ip(ip_int):
    """Convert uint32 to IP address string."""
    try:
        ip_bytes = struct.pack('<L', ip_int)
        #ip_bytes = struct.pack('!L', ip_int)
        return socket.inet_ntoa(ip_bytes)
    except Exception as e:
        print(f"Error converting IP {ip_int}: {e}")
        return None

def process_monero_tsv(input_file, output_file):
    """Process the TSV file with the specific format from tshark."""
    print(f"Processing {input_file} to extract Monero peer lists...")
    
    # Initialize output structure
    output_data = {
        "header": {
            "extraction_date": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "description": "Monero peer list extraction from TSV",
            "input_file": input_file
        },
        "peer_lists": []
    }
    
    # Track statistics
    line_count = 0
    peer_list_count = 0
    total_peer_count = 0
    
    try:
        with open(input_file, 'r') as f:
            for line in f:
                line_count += 1
                
                try:
                    # Split line into main fields (tab-separated)
                    fields = line.strip().split('\t')
                    if len(fields) < 5:
                        continue
                    
                    # Extract the basic fields
                    timestamp_str = fields[0]
                    src_ip = fields[1]
                    keys = fields[2].split(',')
                    types = fields[3].split(',')
                    
                    # Skip if not a peer list
                    if 'local_peerlist_new' not in keys:
                        continue
                    
                    # Extract value arrays
                    values = {
                        '6': fields[4].split(',') if len(fields) > 4 else [],  # uint32
                        '7': fields[5].split(',') if len(fields) > 5 else [],  # uint16
                        '8': fields[6].split(',') if len(fields) > 6 else [],  # uint8
                        '5': fields[7].split(',') if len(fields) > 7 else [],  # uint64
                    }
                    
                    # Convert timestamp
                    timestamp_float = float(timestamp_str)
                    formatted_time = datetime.datetime.fromtimestamp(timestamp_float).strftime('%Y-%m-%d %H:%M:%S')
                    
                    # Create peer list entry
                    peer_list = {
                        "source_ip": src_ip,
                        "timestamp": formatted_time,
                        "peers": []
                    }
                    
                    # Track counters for each value type
                    type_counters = {t: 0 for t in values.keys()}
                    
                    # Find marker positions
                    adr_indices = [i for i, k in enumerate(keys) if k == 'adr']
                    payload_idx = len(keys)
                    if 'payload_data' in keys:
                        payload_idx = keys.index('payload_data')
                    
                    # Process peers - each starting with 'adr'
                    current_peer = None
                    for i in range(len(keys)):
                        key = keys[i]
                        
                        # Start a new peer when we see 'adr'
                        if key == 'adr':
                            # Save previous peer if it exists
                            if current_peer is not None and 'ip' in current_peer:
                                peer_list["peers"].append(current_peer)
                            
                            # Start a new peer
                            current_peer = {}
                            continue
                        
                        # Stop processing peers when we hit payload_data
                        if key == 'payload_data':
                            # Save last peer if needed
                            if current_peer is not None and 'ip' in current_peer:
                                peer_list["peers"].append(current_peer)
                                current_peer = None
                            
                            # Now we're processing metadata
                            continue
                        
                        # Skip if we're not in a peer section
                        if current_peer is None and i >= payload_idx:
                            # We're in metadata section
                            pass
                        elif current_peer is None:
                            # Not in a peer section and not in metadata
                            continue
                        
                        # Get the value based on type
                        if i < len(types):
                            field_type = types[i]
                            
                            if field_type in type_counters and type_counters[field_type] < len(values[field_type]):
                                value = values[field_type][type_counters[field_type]]
                                type_counters[field_type] += 1
                                
                                # Handle special fields for peers
                                if current_peer is not None:
                                    if key == 'm_ip' and field_type == '6':
                                        try:
                                            ip_int = int(value)
                                            ip_str = uint32_to_ip(ip_int)
                                            if ip_str:
                                                current_peer['ip'] = ip_str
                                        except:
                                            pass
                                    elif key == 'm_port' and field_type == '7':
                                        try:
                                            current_peer['port'] = int(value)
                                        except:
                                            pass
                                    elif key == 'type' and field_type == '8':
                                        try:
                                            current_peer['type'] = int(value)
                                        except:
                                            pass
                                    elif key == 'id' and field_type == '5':
                                        current_peer['id'] = value
                                    elif key == 'pruning_seed':
                                        try:
                                            current_peer['pruning_seed'] = int(value)
                                        except:
                                            pass
                                    elif key == 'rpc_port':
                                        try:
                                            current_peer['rpc_port'] = int(value)
                                        except:
                                            pass
                                    else:
                                        # Store any other key directly
                                        current_peer[key] = value
                                
                                # Handle metadata fields (after payload_data)
                                elif i >= payload_idx:
                                    # Store metadata - convert number types
                                    if field_type in ['6', '7', '8']:
                                        try:
                                            peer_list[key] = int(value)
                                        except:
                                            peer_list[key] = value
                                    else:
                                        peer_list[key] = value
                    
                    # Add the final peer if not already added
                    if current_peer is not None and 'ip' in current_peer:
                        peer_list["peers"].append(current_peer)
                    
                    # Only add peer list if it has peers
                    if peer_list["peers"]:
                        output_data["peer_lists"].append(peer_list)
                        total_peer_count += len(peer_list["peers"])
                        peer_list_count += 1
                        
                        # Print progress
                        #if peer_list_count % 1000 == 0 or peer_list_count < 5:
                        #    print(f"Found peer list #{peer_list_count} from {src_ip} with {len(peer_list['peers'])} peers")
                
                except Exception as e:
                    print(f"Error processing line {line_count}: {e}")
        
        # Write the output
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        # Print summary
        print(f"\nProcessing complete!")
        print(f"Total lines processed: {line_count}")
        print(f"Total peer lists extracted: {peer_list_count}")
        print(f"Total peers found: {total_peer_count}")
        
    except Exception as e:
        print(f"Error processing file: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 extract_monero_peers.py input_file.tsv [output_file.json]")
        sys.exit(1)
    
    input_file = sys.argv[1]
    input_file_name = os.path.splitext(os.path.basename(input_file))[0]
    output_file = f"data/peerlists/{input_file_name}_peer_lists.json"
    
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' does not exist")
        sys.exit(1)
    
    process_monero_tsv(input_file, output_file)