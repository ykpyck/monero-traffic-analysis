#!/usr/bin/env python3
import sys
import socket
import struct
import json
import datetime
import os
import logging

logging.basicConfig(level=logging.INFO)

def uint32_to_ip(ip_int):
    """Convert uint32 to IP address string."""
    try:
        ip_bytes = struct.pack('<L', ip_int)
        #ip_bytes = struct.pack('!L', ip_int)
        return socket.inet_ntoa(ip_bytes)
    except Exception as e:
        print(f"Error converting IP {ip_int}: {e}")
        return None
    
def process_node_data(keys, types, values, type_counters, start_idx, end_idx):
    """Process node_data structure."""
    node_data = {}
    
    for i in range(start_idx, end_idx):
        if i >= len(keys) or i >= len(types):
            continue
            
        key = keys[i]
        field_type = types[i]
        
        if field_type in type_counters and type_counters[field_type] < len(values[field_type]):
            value = values[field_type][type_counters[field_type]]
            type_counters[field_type] += 1
            
            # Convert based on type
            if field_type in ['6', '7', '8']:  # uint32, uint16, uint8
                try:
                    node_data[key] = int(value)
                except:
                    node_data[key] = value
            elif field_type in ['5', '11']:  # uint64, boolean
                try:
                    if field_type == '11':  # boolean
                        node_data[key] = bool(int(value)) if value != '' else False
                    else:
                        node_data[key] = int(value) if value != '' else 0
                        #logging.info(f"Value: {value} - int(value): {int(value)}")
                except:
                    node_data[key] = value
            elif field_type == '10':  # string
                node_data[key] = value
            else:
                node_data[key] = value
    
    return node_data if node_data else None

def process_payload_data(keys, types, values, type_counters, start_idx, end_idx):
    """Process payload_data structure."""
    payload_data = {}
    
    for i in range(start_idx, end_idx):
        if i >= len(keys) or i >= len(types):
            continue
            
        key = keys[i]
        field_type = types[i]
        
        if field_type in type_counters and type_counters[field_type] < len(values[field_type]):
            value = values[field_type][type_counters[field_type]]
            type_counters[field_type] += 1
            
            # Convert based on type
            if field_type in ['6', '7', '8']:  # uint32, uint16, uint8
                try:
                    payload_data[key] = int(value)
                except:
                    payload_data[key] = value
            elif field_type in ['5', '11']:  # uint64, boolean
                try:
                    if field_type == '11':  # boolean
                        payload_data[key] = bool(int(value)) if value != '' else False
                    else:
                        payload_data[key] = int(value) if value != '' else 0
                except:
                    payload_data[key] = value
            elif field_type == '10':  # string
                payload_data[key] = value
            else:
                payload_data[key] = value
    
    return payload_data if payload_data else None

def process_peer_list(keys, types, values, type_counters, start_idx, end_idx):
    """Process local_peerlist_new structure."""
    peers = []
    current_peer = None
    
    for i in range(start_idx, end_idx):
        if i >= len(keys):
            break
            
        key = keys[i]
        
        # Start a new peer when we see 'adr'
        if key == 'adr':
            if current_peer is not None and 'ip' in current_peer:
                peers.append(current_peer)
            current_peer = {}
            continue
        
        # Get the value based on type
        if i < len(types):
            field_type = types[i]
            
            if field_type in type_counters and type_counters[field_type] < len(values[field_type]):
                value = values[field_type][type_counters[field_type]]
                type_counters[field_type] += 1
                
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
                    elif key == 'id' and field_type in ['5', '11']:
                        if field_type == '11':
                            try:
                                current_peer['id'] = bool(int(value)) if value != '' else False
                            except:
                                current_peer['id'] = value
                        else:
                            current_peer['id'] = value
                    elif field_type == '10':  # string type
                        current_peer[key] = value
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
                        current_peer[key] = value
    
    # Add the final peer if not already added
    if current_peer is not None and 'ip' in current_peer:
        peers.append(current_peer)
    
    return peers if peers else None

def process_monero_tsv(input_file, output_file):
    """Process the TSV file with the specific format from tshark."""
    print(f"Processing {input_file} to extract Monero peer lists...")
    
    # Initialize output structure
    output_data = {
        "header": {
            "extraction_date": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "description": "Monero packet extraction from TSV - General format",
            "input_file": input_file
        },
        "packets": []  
    }
    
    # Track statistics
    line_count = 0
    packet_count = 0
    peer_list_count = 0
    node_data_count = 0
    payload_data_count = 0
    total_peer_count = 0
    
    try:
        with open(input_file, 'r') as f:
            for line in f:
                line_count += 1
                
                try:
                    # Split line into main fields (tab-separated)
                    fields = line.strip().split('\t')
                    if len(fields) < 7:
                        continue
                    
                    # Extract the basic fields
                    frame_number = fields[0]
                    timestamp_str = fields[1]
                    src_ip = fields[2]
                    dst_ip = fields[3]
                    command = fields[4]
                    flags = fields[5]
                    tcp_segment_count = fields[6]
                    tcp_length = fields[7]
                    src_port = fields[8]
                    dst_port = fields[9]

                    if len(fields) < 13:
                        keys = []
                        types = []
                    else:
                        keys = fields[10].split(',')
                        types = fields[11].split(',')
                    
                    values = {}
                    field_mapping = {
                        '5': 12,   # uint64
                        '6': 13,   # uint32  
                        '7': 14,   # uint16
                        '8': 15,   # uint8
                        '10': 16,  # string
                        '11': 12,  # boolean (sent as uint64)
                    }

                    for type_id, field_idx in field_mapping.items():
                        if field_idx < len(fields):
                            values[type_id] = fields[field_idx].split(',') if fields[field_idx] else []
                        else:
                            values[type_id] = []

                    
                    # Convert timestamp
                    timestamp_float = float(timestamp_str)
                    formatted_time = datetime.datetime.fromtimestamp(timestamp_float).strftime('%Y-%m-%d %H:%M:%S.%f')
                    
                    packet = {
                        "frame_number": frame_number,
                        "source_ip": src_ip,
                        "source_port": src_port,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "timestamp": formatted_time,
                        "command": command,
                        "monero_flags": flags,
                        "tcp_segments": tcp_segment_count,
                        "tcp_length": tcp_length,
                        "local_peerlist_new": None,
                        "node_data": None,
                        "payload_data": None
                    }

                    # Find section boundaries
                    sections = {
                        'local_peerlist_new': None,
                        'node_data': None,
                        'payload_data': None
                    }
                    
                    # Identify section start positions
                    for section_name in sections.keys():
                        if section_name in keys:
                            sections[section_name] = keys.index(section_name)
                    
                    section_order = [(name, pos) for name, pos in sections.items() if pos is not None]
                    section_order.sort(key=lambda x: x[1])
                    
                    type_counters = {'5': 0, '6': 0, '7': 0, '8': 0, '10': 0, '11': 0}

                    for i, (section_name, start_pos) in enumerate(section_order):
                        # Determine end position
                        if i + 1 < len(section_order):
                            end_pos = section_order[i + 1][1]
                        else:
                            end_pos = len(keys)

                        if section_name == 'local_peerlist_new':
                            packet["local_peerlist_new"] = process_peer_list(keys, types, values, type_counters, start_pos + 1, end_pos)
                        elif section_name == 'node_data':
                            packet["node_data"] = process_node_data(keys, types, values, type_counters, start_pos + 1, end_pos)
                        elif section_name == 'payload_data':
                            packet["payload_data"] = process_payload_data(keys, types, values, type_counters, start_pos + 1, end_pos)

                    packet_count += 1
                    if packet["local_peerlist_new"]:
                        peer_list_count += 1
                        total_peer_count += len(packet["local_peerlist_new"])
                    if packet["node_data"]:
                        node_data_count += 1
                    if packet["payload_data"]:
                        payload_data_count += 1

                    output_data["packets"].append(packet)

                except Exception as e:
                    print(f"Error processing line {line_count}: {e}")
        
        # Write the output
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        # Print summary
        print(f"\nProcessing complete!")
        print(f"Total lines processed: {line_count}")
        print(f"Total packets extracted: {packet_count}")
        print(f"Packets with peer lists: {peer_list_count}")
        print(f"Packets with node data: {node_data_count}")
        print(f"Packets with payload data: {payload_data_count}")
        print(f"Total peers found: {total_peer_count}")
        
    except Exception as e:
        print(f"Error processing file: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 extract_monero_peers.py input_file.tsv output_file.json")
        sys.exit(1)
    
    input_file = sys.argv[1]
    input_file_name = os.path.splitext(os.path.basename(input_file))[0]
    output_file = sys.argv[2]
    
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' does not exist")
        sys.exit(1)
    
    process_monero_tsv(input_file, output_file)