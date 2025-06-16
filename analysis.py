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
import ast
from itertools import combinations
import maxminddb

def ip_to_subnet(ip):
   try:
       return str(ipaddress.IPv4Network(f"{ip}/24", strict=False).network_address) + "/24"
   except:
       return None
   
def ip_to_asn(ip_address, db_path='data/external/GeoLite2-ASN.mmdb'):
    try:
        with maxminddb.open_database(db_path) as reader:
            result = reader.get(ip_address)
            return result['autonomous_system_organization']
    except Exception as e:
        return None

def safe_union_arrays(series):
    all_elements = set()
    for item in series:
        if isinstance(item, str):
            try:
                parsed = ast.literal_eval(item)
                if isinstance(parsed, list):
                    all_elements.update(parsed)
                else:
                    all_elements.add(parsed)  # single value
            except:
                continue
    return all_elements
   
def set_plt_latex_format():
    plt.rcParams.update({
        "font.size": 12,          # Base font size
        "axes.titlesize": 12,     # Title size
        "axes.labelsize": 10,     # Axis label size
        "xtick.labelsize": 10,    # X-tick label size
        "ytick.labelsize": 10,    # Y-tick label size
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
    
    return result_df

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
    valid_conns = connection_sizes >= 1
    valid_conn_ids = valid_conns[valid_conns].index
    
    conn_info = []

    for conn_id in valid_conn_ids:
        conn = grouped.get_group(conn_id)
        commands = np.array(conn['command'])
        monero_flags = np.array(conn['monero_flags'])
        timestamps = np.array(conn['timestamp'])
        source_ip = conn['source_ip'].iloc[0]

        conn_row = {
            'source_ip': source_ip,
            'total_pings': 1,
            'ping_frequency': 0,
            'total_handshakes': 1,
            'handshake_frequency': 0
        }

        # Ping Analysis
        ping_mask = (commands == '1003')
        ping_timestamps = timestamps[ping_mask]
        if len(ping_timestamps) > 1:
            ping_series = pd.Series(ping_timestamps)
            ping_differences = ping_series.diff().dt.total_seconds().dropna()

            conn_row['total_pings'] = len(ping_timestamps)
            conn_row['ping_frequency'] = ping_differences.mean()
        
        # Handshake Analysis
        handshake_mask = (commands == '1001')
        handshake_timestamps = timestamps[handshake_mask]
        if len(handshake_timestamps) > 1:
            handshake_series = pd.Series(handshake_timestamps)
            handshake_diffs = handshake_series.diff().dt.total_seconds().dropna()

            conn_row['total_handshakes'] = len(handshake_timestamps)
            conn_row['handshake_frequency'] = handshake_diffs.mean()
        
        conn_info.append(conn_row)
    
    conn_df = pd.DataFrame(conn_info)

    ping_frequency_by_ip = conn_df.groupby('source_ip')['ping_frequency'].mean()
    pings_by_ip = conn_df.groupby('source_ip')['total_pings'].max()
    result_df['ping_frequency'] = result_df['source_ip'].map(ping_frequency_by_ip)
    result_df['total_pings'] = result_df['source_ip'].map(pings_by_ip)

    handshake_frequency_by_ip = conn_df.groupby('source_ip')['handshake_frequency'].mean()
    handshakes_by_ip = conn_df.groupby('source_ip')['total_handshakes'].max()
    result_df['handshake_frequency'] = result_df['source_ip'].map(handshake_frequency_by_ip)
    result_df['total_handshakes'] = result_df['source_ip'].map(handshakes_by_ip)

    return result_df


def analyze_global_pl_similarity(peers_df, node, result_df):
    '''Analyzes the global peer list of a peer where each peer list is aggregated and reduced to a unique set of peers.'''
    
    unique_peers_by_source = peers_df.groupby('source_ip')['ip'].apply(lambda x: x.unique().tolist()).reset_index()
    unique_peers_by_source.columns = ['source_ip', 'unique_peer_ips']
    #print(unique_peers_by_source.head())
    
    unique_peers_by_source['peer_count'] = unique_peers_by_source['unique_peer_ips'].apply(len)
    unique_peers_by_source = unique_peers_by_source[unique_peers_by_source['peer_count'] > 249]
    
    peer_sets = {row['source_ip']: set(row['unique_peer_ips']) 
                for _, row in unique_peers_by_source.iterrows()}

    # pairwise overlaps
    overlaps = []
    for source1, source2 in combinations(peer_sets.keys(), 2):
       intersection = len(peer_sets[source1] & peer_sets[source2])
       union = len(peer_sets[source1] | peer_sets[source2])
       jaccard = intersection / union if union > 0 else 0
    
       overlaps.append({
           'source1': source1, 'source2': source2,
           'intersection': intersection, 'jaccard_similarity': jaccard,
           'union': union
       })
    
    overlap_df = pd.DataFrame(overlaps)

    max_sim_by_ip = overlap_df.groupby('source1')['jaccard_similarity'].max()
    result_df['max_pl_sim'] = result_df['source_ip'].map(max_sim_by_ip)

    SIMILARITY_THRESHOLD = result_df['max_pl_sim'].quantile(0.95)
    high_sim_pairs = overlap_df[overlap_df['jaccard_similarity'] >= SIMILARITY_THRESHOLD].copy()

    groups = []

    for _, row in high_sim_pairs.iterrows():
        source1, source2 = row['source1'], row['source2']
        sim = row['jaccard_similarity']

        found_group = None
        for group in groups:
            if source1 in group['sources'] or source2 in group['sources']:
                found_group = group
                break
            
        if not found_group is None:
            found_group['sources'].add(source1)
            found_group['sources'].add(source2)
            found_group['similarities'].append(sim)
        else:
            groups.append({
                'sources': {source1, source2},
                'similarities': [sim]
            })

    source_to_group = {}

    for i, group in enumerate(groups):
        if len(group['sources']) > 1:
            sources_list = list(group['sources'])
            for source_ip in sources_list:
                source_to_group[source_ip] = i
    
    result_df[f'sim_group_{node}'] = result_df['source_ip'].map(source_to_group)

    return result_df

def calc_diversity(ip_list):
    subnets = set()
    valid_count = 0
    
    for ip in ip_list:
        try:
            subnet = str(ipaddress.IPv4Network(f"{ip}/24", strict=False).network_address) + "/24"
            subnets.add(subnet)
            valid_count += 1
        except:
            continue
    
    return len(subnets) / valid_count if valid_count > 0 else 0

def analyze_local_pl_similarity(peers_df, node, result_df):
    pl_by_source = peers_df.groupby('pl_identifier').agg({
        'ip': lambda x: x.tolist(),
        'source_ip': 'first',
        }).reset_index()
    pl_by_source.columns = ['source_pl', 'peer_ips', 'source_ip']
    #print(unique_peers_by_source.head())

    pl_by_source['peer_count'] = pl_by_source['peer_ips'].apply(len)
    pl_by_source = pl_by_source[pl_by_source['peer_count'] > 249]

    pl_sets = {row['source_pl']: set(row['peer_ips']) 
                for _, row in pl_by_source.iterrows()}

    source_ip_lookup = pl_by_source.set_index('source_pl')['source_ip'].to_dict()

    overlaps = []
    for source1, source2 in combinations(pl_sets.keys(), 2):
       intersection = len(pl_sets[source1] & pl_sets[source2])
       union = len(pl_sets[source1] | pl_sets[source2])
       jaccard = intersection / union if union > 0 else 0
    
       overlaps.append({
            'source1': source1, 
            'source2': source2,
            'source1_ip': source_ip_lookup[source1],
            'source2_ip': source_ip_lookup[source2],
            'intersection': intersection, 
            'jaccard_similarity': jaccard,
            'union': union
        })
    
    overlap_df = pd.DataFrame(overlaps)

    overlap_df.to_csv(f'results/node_results/{node}_pl_df.csv', index=False)

    pl_by_source['avg_pl_diversity'] = pl_by_source['peer_ips'].apply(calc_diversity)

    mean_pl_div = pl_by_source.groupby('source_ip')['avg_pl_diversity'].mean()
    result_df['avg_pl_diversity'] = result_df['source_ip'].map(mean_pl_div)

    return result_df

def process_node_data(folder_path):
    peer_packets_df, peers_df = load_json(folder_path=folder_path) 
    # some data cleaning
    possible_flags = ['1', '2', '1,2', '2,1', '1,1']
    peer_packets_df = peer_packets_df[peer_packets_df['monero_flags'].isin(possible_flags)]
    peer_packets_df['timestamp'] = pd.to_datetime(peer_packets_df['timestamp'])

    result_df = create_result_df(peer_packets_df)

    result_df = analyze_ts_latency(peer_packets_df, result_df)

    result_df = analyze_connections(peer_packets_df, result_df)

    node = str.split(str(folder_path), '/')[-1]

    result_df = analyze_global_pl_similarity(peers_df, node, result_df)

    result_df = analyze_local_pl_similarity(peers_df, node, result_df)

    result_df.to_csv(f'results/node_results/{node}_result_df.csv', index=False)

    

def plot_connection_analysis(result_df):
    # Timed Sync Analysis
    quantiles = [0.25, 0.50, 0.75, 0.90, 0.95, 0.99]
    set_plt_latex_format()
    plt.figure(figsize=(3.13, 2), dpi=300)
    plt.hist(result_df['ts_latency'], bins=1000, log=True)
    plt.xlim(50, 180)
    plt.axvline(result_df['ts_latency'].quantile(0.5), color='orange', linestyle='--', label='50th')
    plt.axvline(result_df['ts_latency'].quantile(0.95), color='green', linestyle='--', label='95th')
    plt.axvline(result_df['ts_latency'].quantile(0.75), color='red', linestyle=':', label='75th')
    outlier_count = sum(x > 180 for x in result_df['ts_latency'])
    plt.text(0.95, 0.45, f'{outlier_count} outliers $>$ 180', fontsize=10,
             transform=plt.gca().transAxes, ha='right', va='top',
             bbox=dict(boxstyle='round,pad=0.3', facecolor='lightgray', alpha=0.7))
    plt.xlabel(f'Latency (s)')
    plt.xticks([60,90,120,150])
    plt.ylabel(f'Count (log scale)')
    plt.legend(title='Percentiles', fontsize=10, title_fontsize=10)
    plt.tight_layout(pad=0.2)
    plt.savefig('results/graphs/ts_latency_dist.pdf')
    print("-"*25)
    print(f"Timed Sync Latency Analysis")
    print("-"*25)
    print(f"Averaged over {len(result_df['ts_latency'])} individual connections: {np.mean(result_df['ts_latency'])}")
    print(f"Percentile distribution: ")
    for quantile in quantiles:
        print(f"    {quantile}th percentile: {result_df['ts_latency'].quantile(quantile)}")

    # Ping Plots
    quantiles = [0.50, 0.75, 0.90, 0.95, 0.99]
    print("-"*25)
    print(f"Ping Analysis")
    print("-"*25)
    print(f"{len(result_df['total_pings'])} connections.")
    print(f"Percentile distribution of number of Pings sent per connection: ")
    for quantile in quantiles:
        print(f"    {quantile}th percentile: {result_df['total_pings'].quantile(quantile)}")
    print(f"Percentile distribution of frequency of Pings if more than one is sent: ")
    for quantile in quantiles:
        print(f"    {quantile}th percentile: {result_df['ping_frequency'].quantile(quantile)}")
    
    plt.figure(figsize=(3.13, 2), dpi=300)
    plt.hist(result_df['total_pings'], bins=40, range=(0, 40), log=True)
    plt.xlim(0, 40)
    plt.axvline(result_df['total_pings'].quantile(0.95), color='green', linestyle='--', label='95th')
    plt.axvline(result_df['total_pings'].quantile(0.9), color='red', linestyle=':', label='90th')

    outlier_count = sum(x > 40 for x in result_df['total_pings'])
    plt.text(0.55, 0.93, f'{outlier_count} outliers $>$ 40', fontsize=10,
             transform=plt.gca().transAxes, ha='right', va='top',
             bbox=dict(boxstyle='round,pad=0.3', facecolor='lightgray', alpha=0.7))
    plt.xlabel(f'Pings per connection')
    plt.ylabel(f'Count (log scale)')
    plt.legend(title='Percentiles', fontsize=10, title_fontsize=10)
    plt.tight_layout(pad=0.2)
    plt.savefig('results/graphs/ping_dist.pdf')
    
    plt.figure(figsize=(3.13, 2), dpi=300)
    plt.hist(result_df['ping_frequency'], bins=120, range=(0, 120), log=True)
    plt.xlim(0, 120)
    plt.axvline(result_df['ping_frequency'].quantile(0.95), color='green', linestyle='--', label='95th')
    plt.axvline(result_df['ping_frequency'].quantile(0.9), color='red', linestyle=':', label='90th')
    
    outlier_count = sum(x > 120 for x in result_df['ping_frequency'])
    plt.text(0.55, 0.93, f'{outlier_count} outliers $>$ 120', fontsize=10,
             transform=plt.gca().transAxes, ha='right', va='top',
             bbox=dict(boxstyle='round,pad=0.3', facecolor='lightgray', alpha=0.7))
    plt.xlabel(f'Frequency of pings (s)')
    plt.ylabel(f'Count (log scale)')
    plt.legend(title='Percentiles', fontsize=10, title_fontsize=10)
    plt.tight_layout(pad=0.2)
    plt.savefig('results/graphs/ping_frequency_dist.pdf')

    # Handshake Plots
    quantiles = [0.50, 0.75, 0.90, 0.95, 0.99, 0.999]
    print("-"*25)
    print(f"Handshake Analysis")
    print("-"*25)
    print(f"{len(result_df['total_handshakes'])} connections.")
    print(f"Percentile distribution of number of Handshakes sent per connection: ")
    for quantile in quantiles:
        print(f"    {quantile}th percentile: {result_df['total_handshakes'].quantile(quantile)}")
    print(f"Percentile distribution of frequency of Handshakes if more than one is sent: ")
    for quantile in quantiles:
        print(f"    {quantile}th percentile: {result_df['handshake_frequency'].quantile(quantile)}")
    
    plt.figure(figsize=(3.13, 2), dpi=300)
    plt.hist(result_df['total_handshakes'], bins=40, range=(0, 40), log=True)
    plt.xlim(0, 40)
    plt.axvline(result_df['total_handshakes'].quantile(0.99), color='green', linestyle='--', label='99th')
    plt.axvline(result_df['total_handshakes'].quantile(0.999), color='red', linestyle=':', label='999th')

    outlier_count = sum(x > 40 for x in result_df['total_handshakes'])
    plt.text(0.55, 0.93, f'{outlier_count} outliers $>$ 40', fontsize=10,
             transform=plt.gca().transAxes, ha='right', va='top',
             bbox=dict(boxstyle='round,pad=0.3', facecolor='lightgray', alpha=0.7))
    plt.xlabel(f'Handshakes per connection')
    plt.ylabel(f'Count (log scale)')
    plt.legend(title='Percentiles', fontsize=10, title_fontsize=10)
    plt.tight_layout(pad=0.2)
    plt.savefig('results/graphs/handshake_dist.pdf')
    
    plt.figure(figsize=(3.13, 2), dpi=300)
    plt.hist(result_df['handshake_frequency'], bins=120, range=(0, 120), log=True)
    plt.xlim(0, 120)
    plt.axvline(result_df['handshake_frequency'].quantile(0.50), color='green', linestyle='--', label='50th')
    plt.axvline(result_df['handshake_frequency'].quantile(0.75), color='red', linestyle=':', label='75th')
    
    outlier_count = sum(x > 120 for x in result_df['handshake_frequency'])
    plt.text(0.55, 0.93, f'{outlier_count} outliers $>$ 120', fontsize=10,
             transform=plt.gca().transAxes, ha='right', va='top',
             bbox=dict(boxstyle='round,pad=0.3', facecolor='lightgray', alpha=0.7))
    plt.xlabel(f'Frequency of handshakes (s)')
    plt.ylabel(f'Count (log scale)')
    plt.legend(title='Percentiles', fontsize=10, title_fontsize=10)
    plt.tight_layout(pad=0.2)
    plt.savefig('results/graphs/handshake_frequency_dist.pdf')

def plot_subnets(global_result_df):
    print("-"*25)
    print(f"ASN Subnet Analysis")
    print("-"*25)
    print(f"Total of {len(global_result_df['source_ip'])} IPs and {len(global_result_df['subnet'].unique())} subnets")
    print(f"Overall distribution of subnets: ")
    quantiles = [0.5, 0.75, 0.9, 0.95, 0.99]
    for q in quantiles:
        print(f"    {q}th: {global_result_df['subnet'].value_counts().quantile(q)}")
    print(f"and {len(global_result_df['asn'].unique())} ASNs")
    print(f"Overall distribution of ASNs: ")
    quantiles = [0.5, 0.75, 0.9, 0.95, 0.99]
    for q in quantiles:
        print(f"    {q}th: {global_result_df['asn'].value_counts().quantile(q)}")

    top_subnets = global_result_df['subnet'].value_counts().head(20)

    plot_data = []
    for subnet in top_subnets.index:
        count = top_subnets[subnet]
        asn = global_result_df[global_result_df['subnet'] == subnet]['asn'].iloc[0]
        plot_data.append({'subnet': subnet, 'count': count, 'asn': asn})

    plot_df = pd.DataFrame(plot_data)
    plot_df = plot_df.sort_values('count')

    # color mapping for ASNs
    unique_asns = plot_df['asn'].unique()
    cmap = plt.cm.tab20
    colors = [cmap(i / len(unique_asns)) for i in range(len(unique_asns))]
    #colors, custom_cmap = retrieve_color_palette(n_colors=len(unique_asns), blends=['#c40d1e', '#9013fe', '#49cb40']) 
    asn_color_map = dict(zip(unique_asns, colors))

    bar_colors = [asn_color_map[asn] for asn in plot_df['asn']]

    fig, ax = plt.subplots(figsize=(6.27, 4), dpi=300)
    bars = ax.barh(range(len(plot_df)), plot_df['count'], color=bar_colors)

    ax.set_yticks(range(len(plot_df)))
    ax.set_yticklabels(plot_df['subnet'])

    # ASN labels
    for i, (bar, asn) in enumerate(zip(bars, plot_df['asn'])):
        width = bar.get_width()
        if i < 15:
            ax.text(width + 0.01 * max(plot_df['count']), bar.get_y() + bar.get_height()/2, 
                f'{asn}', ha='left', va='center', fontsize=8)
        else:
            ax.text(width/5 + 0.01 * max(plot_df['count']), bar.get_y() + bar.get_height()/2, 
                f'{asn}', ha='left', va='center', fontsize=8)

    ax.set_xlabel('Count')
    ax.set_ylabel('Subnet')

    plt.tight_layout()
    plt.savefig('results/graphs/asn_subnet_dist.pdf')
    
def plot_global_pl_sim(global_result_df):
    plt.figure(figsize=(3.13, 2), dpi=300)
    plt.hist(global_result_df['max_pl_sim'], log=True, bins=100)
    plt.axvline(global_result_df['max_pl_sim'].quantile(0.50), color='green', linestyle=':', label='50th')
    plt.axvline(global_result_df['max_pl_sim'].quantile(0.9), color='orange', linestyle='--', label='90th')
    plt.axvline(global_result_df['max_pl_sim'].quantile(0.95), color='red', linestyle=':', label='99th')
    plt.xlabel(f'Max similarity per peer')
    plt.ylabel(f'Count (log scale)')
    plt.legend(title='Percentiles', fontsize=10, title_fontsize=10)
    plt.tight_layout(pad=0.2)
    plt.show()

def plot_pl_similarities(global_pl_df):
    plt.figure(figsize=(3.13, 2), dpi=300)
    plt.hist(global_pl_df['jaccard_similarity'], bins=100, log=True)
    plt.axvline(global_pl_df['jaccard_similarity'].quantile(0.50), color='green', linestyle=':', label='50th')
    plt.axvline(global_pl_df['jaccard_similarity'].quantile(0.99), color='orange', linestyle='--', label='99th')
    plt.axvline(global_pl_df['jaccard_similarity'].quantile(0.999), color='red', linestyle=':', label='999th')
    plt.xlabel(f'Peer list similarities')
    plt.ylabel(f'Count (log scale)')
    plt.legend(title='Percentiles', fontsize=10, title_fontsize=10)
    plt.tight_layout(pad=0.2)
    plt.savefig("results/graphs/pl_sims.pdf")
    
    pl_similarity_threshold = global_pl_df['jaccard_similarity'].quantile(0.99)
    high_sim_df = global_pl_df[global_pl_df['jaccard_similarity']>pl_similarity_threshold]

    all_ips = pd.concat([
        high_sim_df['source1_ip'], 
        high_sim_df['source2_ip']
    ])

    # Get value counts for all IPs
    combined_ip_counts = all_ips.value_counts()

    # Plot combined results
    top_ips = combined_ip_counts.head(20)
    others_count = combined_ip_counts.iloc[20:].sum()

    plt.figure(figsize=(3.13, 2), dpi=300)
    plt.bar(range(len(top_ips)), top_ips.values, label='Top 20 Individual IPs')
    plt.bar(len(top_ips), others_count, color='red', 
            label=f'Others ({len(combined_ip_counts) - 20} IPs)')
    plt.yscale('log')
    plt.xlabel('IPs')
    plt.ylabel('Count (log scale)')
    #plt.title('IP Frequency')
    plt.legend(fontsize=8)
    plt.tight_layout(pad=0.2)
    plt.savefig("results/graphs/high_pl_sim_peers.pdf")

def plot_pl_diversities(global_result_df):
    plt.figure(figsize=(3.13, 2), dpi=300)
    inverted_data = 1 - global_result_df['avg_pl_diversity']
    plt.hist(inverted_data, bins=100, log=True)
    plt.axvline(inverted_data.quantile(0.50), color='green', linestyle=':', label='50th')
    plt.axvline(inverted_data.quantile(0.90), color='orange', linestyle='--', label='90th')
    plt.axvline(inverted_data.quantile(0.95), color='red', linestyle=':', label='95th')
    plt.xlabel(f'Peer list diversities (inverted)')
    plt.ylabel(f'Count (log scale)')
    plt.legend(title='Percentiles', fontsize=10, title_fontsize=10)
    plt.tight_layout(pad=0.2)
    plt.savefig("results/graphs/high_pl_sim_peers.pdf")

def combine_and_avg():
    node_results_path = Path('results/node_results')
    dfs = []
    for csv_file in node_results_path.glob("*_result_df.csv"):
        df = pd.read_csv(csv_file)
        dfs.append(df)

    combined_df = pd.concat(dfs, ignore_index=True)

    grouped = combined_df.groupby('source_ip')

    global_result_df = pd.DataFrame()

    global_result_df['source_ip'] = grouped['source_ip'].first()
    global_result_df['packet_count'] = grouped['packet_count'].sum()
    global_result_df['unique_commands'] = grouped['unique_commands'].sum()
    global_result_df['unique_my_ports'] = grouped['unique_my_ports'].apply(safe_union_arrays)
    global_result_df['unique_peer_ids'] = grouped['unique_peer_ids'].apply(safe_union_arrays)
    global_result_df['has_support_flags'] = grouped['has_support_flags'].any()
    global_result_df['unique_source_ports'] = grouped['unique_source_ports'].mean()
    global_result_df['ts_latency'] = grouped['ts_latency'].mean()
    global_result_df['ping_frequency'] = grouped['ping_frequency'].mean()
    global_result_df['total_pings'] = grouped['total_pings'].mean()
    global_result_df['handshake_frequency'] = grouped['handshake_frequency'].mean()
    global_result_df['total_handshakes'] = grouped['total_handshakes'].mean()
    global_result_df['subnet'] = global_result_df['source_ip'].apply(ip_to_subnet)
    global_result_df['asn'] = global_result_df['source_ip'].apply(ip_to_asn)
    global_result_df['max_pl_sim'] = grouped['max_pl_sim'].mean()
    global_result_df['avg_pl_diversity'] = grouped['avg_pl_diversity'].mean()

    group_columns = [col for col in combined_df.columns if col.startswith('sim_group_')]
    for col in group_columns:
        global_result_df[col] = grouped[col].sum()

    dfs = []
    for csv_file in node_results_path.glob("*_pl_df.csv"):
        df = pd.read_csv(csv_file)
        dfs.append(df)

    global_pl_df = pd.concat(dfs, ignore_index=True)

    return global_result_df, global_pl_df

def main():
    # for loop to analyze each folder on its own (data cannot simply be merged as it would break things like timing analysis if peers from multiple nodes overlap connection timings)
    packets_path = Path("data/packets")

    for folder_path in packets_path.iterdir():
        if folder_path.is_dir() and not 'archive' in str.split(str(folder_path), '/'):
            print(f"Processing {folder_path}...")
            process_node_data(folder_path)
    
    global_result_df, global_pl_df = combine_and_avg()

    plot_connection_analysis(global_result_df)

    plot_subnets(global_result_df)

    #plot_global_pl_sim(global_result_df)

    plot_pl_similarities(global_pl_df)

    plot_pl_diversities(global_result_df)

if __name__ == '__main__':
    main()