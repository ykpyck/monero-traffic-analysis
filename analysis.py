#!/usr/bin/env python3

import ipaddress
import json
import pandas as pd
import matplotlib.pyplot as plt
from collections import defaultdict
from datetime import datetime, timedelta
import numpy as np
from pathlib import Path
from collections import Counter

def ip_to_subnet(ip):
   try:
       return str(ipaddress.IPv4Network(f"{ip}/24", strict=False).network_address) + "/24"
   except:
       return None
   
def set_plt_latex_format():
    plt.rcParams.update({
        "font.size": 12,          # Base font size
        "axes.titlesize": 12,     # Title size
        "axes.labelsize": 12,     # Axis label size
        "xtick.labelsize": 12,    # X-tick label size
        "ytick.labelsize": 12,    # Y-tick label size
        "legend.fontsize": 12,    # Legend font size
        "figure.titlesize": 12,    # Figure title size
        "text.usetex": True,
        "font.family": "serif",
        "font.serif": ["Computer Modern Roman"]
    })

def write_tex(results):
    
    tot_unique_IPs = results['']        # number of unique IPs
    num_last_seen_IPs = results['']     # number of unique IPs that transmitted at least once a last_seen field in their peer lists
    num_sup_flags_IPs = results['']     # number of unique IPs that transmitted at least once a last_seen field in their peer lists


    with open('results.tex', 'w') as f:
        for cmd_name, value in results.items():
            f.write(f"\\newcommand{{\\{cmd_name}}}{{{value}}}\n")

def load_json(folder_path):
    # load all jsons
    all_packets = []
    all_peers = []

    for json_file in folder_path.glob("*.json"):
       with open(json_file, 'r') as f:
           data = json.load(f)
    
       for packet in data['packets']:
            packet_meta = {k: v for k, v in packet.items() if not k in ['local_peerlist_new', 'node_data', 'payload_data']}

            if not packet['node_data'] is None:
                for k, v in packet['node_data'].items():
                    packet_meta[k] = v
            if not packet['payload_data'] is None:
                for k, v in packet['payload_data'].items(): 
                    packet_meta[k] = v

            if not packet['local_peerlist_new'] is None:
                packet['peerlist_length'] = len(packet['local_peerlist_new'])
                for peer in packet['local_peerlist_new']:
                    peer_data = peer.copy()
                    peer_data['source_ip'] = packet['source_ip']
                    peer_data['timestamp'] = packet['timestamp']
                    peer_data['pl_identifier'] = packet['timestamp'] + '_' + packet['source_ip']
                    all_peers.append(peer_data)

            all_packets.append(packet_meta)

    return pd.DataFrame(all_packets), pd.DataFrame(all_peers)
    
def analyze_ts_latency(peer_packets_df, result_df):
    all_data = peer_packets_df.copy()
    all_data = all_data.sort_values(['source_ip', 'timestamp'])

    all_data['source_ip_cat'] = all_data['source_ip'].astype('category')

    # shift to later compare current vs prev IP
    all_data['prev_ip'] = all_data['source_ip_cat'].shift(1) 
    all_data['time_diff'] = all_data['timestamp'].diff().dt.total_seconds()

    # mask logic to identify breaks if IP changes, time is bigger 120s (idle), first row, handshake
    all_data['is_break'] = (all_data['source_ip_cat'] != all_data['prev_ip']) | (all_data['time_diff'] > 120) | (all_data['time_diff'].isna()) | (all_data['command'] == '1001')
    all_data['connection_id'] = all_data['is_break'].cumsum()

    # filter already for valid conns
    grouped = all_data.groupby('connection_id')
    connection_sizes = grouped.size()
    valid_conns = connection_sizes >= 2
    valid_conn_ids = valid_conns[valid_conns].index

    all_ts_diffs = []
    all_conn_avgs = []              # TODO: replace with dataframe to save memory
    conn_info = []

    for conn_id in valid_conn_ids:
        conn = grouped.get_group(conn_id)
        commands = np.array(conn['command'])
        monero_flags = np.array(conn['monero_flags'])
        timestamps = np.array(conn['timestamp'])
        ts_mask = (commands == '1002') & (monero_flags == '1')
        ts_series = pd.Series(timestamps[ts_mask])

        # Get source IP for this connection
        source_ip = conn['source_ip'].iloc[0]

        if len(ts_series) > 2:
            differences = ts_series.diff().dt.total_seconds().dropna()
            all_ts_diffs.extend(differences)
            latency = differences.mean()
            all_conn_avgs.append(latency)

            # Append connection info for efficient processing
            conn_info.append({'source_ip': source_ip, 'latency': latency})
        else:
            # If no valid latency, still record the IP with None
            conn_info.append({'source_ip': source_ip, 'latency': None})

    conn_df = pd.DataFrame(conn_info)

    # Calculate average latency per IP (handles None values automatically)
    latency_by_ip = conn_df.groupby('source_ip')['latency'].mean()

    # Add to result_df
    result_df['ts_latency'] = result_df['source_ip'].map(latency_by_ip)
    
    #print(f"\n{all_ts_diffs[:5]}")
    #print(f"{all_conn_avgs[:5]}")

    percentiles = [25, 50, 75, 90, 95, 99]
    '''
    plt.hist(all_ts_diffs, bins=1000, log=True)
    #plt.axvline(np.mean(all_ts_diffs), color='red', linestyle='--', label='mean')
    plt.axvline(np.median(all_ts_diffs), color='orange', linestyle='--', label='median')
    #plt.axvline(np.percentile(all_ts_diffs, 25), color='green', linestyle=':', label='25th')
    plt.axvline(np.percentile(all_ts_diffs, 90), color='red', linestyle=':', label='75th')
    plt.legend()
    plt.show()
    print(f"{len(all_ts_diffs)} Timed Sync differences.")
    print(f"Averaged over all time differences: {np.mean(all_ts_diffs)}")
    print(f"Percentile distribution: ")
    for percentile in percentiles:
        print(f"{percentile}th percentile: {np.percentile(all_ts_diffs, percentile)}")
    '''
    set_plt_latex_format()
    plt.figure(figsize=(3.13, 2), dpi=300)
    plt.hist(all_conn_avgs, bins=1000, log=True)
    plt.xlim(50, 180)
    plt.axvline(np.median(all_conn_avgs), color='orange', linestyle='--', label='median')
    plt.axvline(np.percentile(all_conn_avgs, 95), color='green', linestyle=':', label='95th')
    plt.axvline(np.percentile(all_conn_avgs, 75), color='red', linestyle=':', label='75th')
    outlier_count = sum(x > 180 for x in all_conn_avgs)
    plt.text(0.95, 0.95, f'{outlier_count} outliers $>$ 180', 
             transform=plt.gca().transAxes, ha='right', va='top',
             bbox=dict(boxstyle='round,pad=0.3', facecolor='lightgray', alpha=0.7))
    plt.xlabel(f'Latency (ms)')
    plt.ylabel(f'Count (log scale)')
    plt.legend()
    plt.savefig('results/graphs/ts_latency_dist.pdf')
    print(f"\nTimed Sync Latency Analysis:")
    print(f"Averaged over {len(all_conn_avgs)} individual connections: {np.mean(all_conn_avgs)}")
    print(f"Percentile distribution: ")
    for percentile in percentiles:
        print(f"    {percentile}th percentile: {np.percentile(all_conn_avgs, percentile)}")
    
    return result_df
    
def create_result_df(peer_packets_df):
    grouped = peer_packets_df.groupby('source_ip')
    
    # Initialize result dictionary
    result_data = {
        'source_ip': [],
        'packet_count': [],
        'unique_commands': [],
        'unique_my_ports': [],
        'unique_peer_ids': [],
        'has_support_flags': [],
        'unique_source_ports': [],
    }

    for source_ip, group in grouped:
        result_data['source_ip'].append(source_ip)
        
        # Basic counts
        result_data['packet_count'].append(len(group))
        
        # Commands analysis
        unique_commands = group['command'].dropna().unique()
        result_data['unique_commands'].append(len(unique_commands))
        
        # My ports analysis
        unique_my_ports = group['my_port'].dropna().unique()
        result_data['unique_my_ports'].append([int(x) for x in unique_my_ports if not pd.isna(x)])
        
        # Peer IDs analysis
        unique_peer_ids = group['peer_id'].dropna().unique()
        result_data['unique_peer_ids'].append([int(x) for x in unique_peer_ids if not pd.isna(x)])
        
        # Support flags analysis
        support_flags_mask = group['support_flags'].notna()
        result_data['has_support_flags'].append(support_flags_mask.any())
        
        # Temporal analysis TBD
        
        # Source ports analysis
        unique_source_ports = group['source_port'].nunique()
        result_data['unique_source_ports'].append(unique_source_ports)

    return pd.DataFrame(result_data)

def analyze_connections(peer_packets_df, result_df):
    # for connection visualization stick to IP and dont split the connection for repeated Handshakes (known pattern)
    all_data = peer_packets_df.copy()
    all_data = all_data.sort_values(['source_ip', 'timestamp'])

    all_data['source_ip_cat'] = all_data['source_ip'].astype('category')

    # shift to later compare current vs prev IP
    all_data['prev_ip'] = all_data['source_ip_cat'].shift(1) 
    all_data['time_diff'] = all_data['timestamp'].diff().dt.total_seconds()

    # mask logic to identify breaks if IP changes, time is bigger 120s (idle connection), or first row
    all_data['is_break'] = (all_data['source_ip_cat'] != all_data['prev_ip']) | (all_data['time_diff'] > 120) | (all_data['time_diff'].isna())
    all_data['connection_id'] = all_data['is_break'].cumsum()

    # filter already for valid conns
    grouped = all_data.groupby('connection_id')
    connection_sizes = grouped.size()

def process_node_data(folder_path):
    peer_packets_df, peers_df = load_json(folder_path=folder_path) 
    # some data cleaning
    possible_flags = ['1', '2', '1,2', '2,1', '1,1']
    peer_packets_df = peer_packets_df[peer_packets_df['monero_flags'].isin(possible_flags)]
    peer_packets_df['timestamp'] = pd.to_datetime(peer_packets_df['timestamp'])

    result_df = create_result_df(peer_packets_df)

    result_df = analyze_ts_latency(peer_packets_df, result_df)



    result_df.to_csv('results/result_df.csv')


def main():
    # for loop to analyze each folder on its own (data cannot simply be merged as it would break things like timing analysis if peers from multiple nodes overlap connection timings)
    packets_path = Path("data/packets")

    for folder_path in packets_path.iterdir():
        if folder_path.is_dir() and not 'archive' in str.split(str(folder_path), '/'):
            process_node_data(folder_path)

if __name__ == '__main__':
    main()