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
import matplotlib.colors as mcolors
import maxminddb
from itertools import combinations
from constants import servers
import networkx as nx
import logging
import sys

logging.basicConfig(level=logging.INFO)

def set_plt_latex_format():
    plt.rcParams.update({
        "font.size": 10,          # Base font size
        "axes.titlesize": 10,     # Title size
        "axes.labelsize": 8,     # Axis label size
        "xtick.labelsize": 8,    # X-tick label size
        "ytick.labelsize": 8,    # Y-tick label size
        "legend.fontsize": 8,    # Legend font size
        "figure.titlesize": 10,    # Figure title size
        "text.usetex": True,
        "font.family": "serif",
        "font.serif": ["Computer Modern Roman"]
    })

# CONNECTION ANOMALIES: Ping, TS Latency,  

def get_connection_info(row, my_ip, default_port):
    # Determine if outgoing (my_ip uses ephemeral port) or incoming (peer uses ephemeral port)
    if row['source_ip'] == my_ip and row['source_port'] != default_port:
        # Outgoing: my port is ephemeral
        return 'outgoing', row['dst_ip'], f"{my_ip}:{row['source_port']}->{row['dst_ip']}:{row['dst_port']}"
    elif row['source_ip'] != my_ip and row['dst_port'] != default_port:
        # Outgoing: peer is responding, but connection was initiated by me
        return 'outgoing', row['source_ip'], f"{my_ip}:{row['dst_port']}->{row['source_ip']}:{row['source_port']}"
    elif row['source_ip'] == my_ip and row['source_port'] == default_port:
        # Incoming: my port is default
        return 'incoming', row['dst_ip'], f"{my_ip}:{default_port}<-{row['dst_ip']}:{row['dst_port']}"
    elif row['source_ip'] != my_ip and row['dst_port'] == default_port:
        # Incoming: I'm responding, but connection was initiated by peer
        return 'incoming', row['source_ip'], f"{my_ip}:{default_port}<-{row['source_ip']}:{row['source_port']}"
    
def analyze_node_connections(peer_packets_df, my_ip, default_port, threshold):
    all_data = peer_packets_df.copy()
    connection_info = all_data.apply(get_connection_info, axis=1, args=(my_ip, default_port))
    all_data['direction'] = [info[0] for info in connection_info]
    all_data['peer_ip'] = [info[1] for info in connection_info]
    all_data['connection_key'] = [info[2] for info in connection_info]
    
    # Sort by connection and timestamp
    all_data = all_data.sort_values(['connection_key', 'timestamp'])
    all_data['connection_key_cat'] = all_data['connection_key'].astype('category')
    all_data['prev_connection'] = all_data['connection_key_cat'].shift(1)
    all_data['time_diff'] = all_data['timestamp'].diff().dt.total_seconds()
    
    # Identify connection breaks
    all_data['is_break'] = (
        (all_data['connection_key_cat'] != all_data['prev_connection']) |
        (all_data['time_diff'] > 120) |
        (all_data['time_diff'].isna())
    )
    all_data['connection_id'] = all_data['is_break'].cumsum()
    grouped = all_data.groupby('connection_id')
    
    # initial conn_df with basic info
    valid_conn_ids = grouped.size()[grouped.size() >= 2].index
    conn_info = []
    
    for conn_id in valid_conn_ids:
        conn = grouped.get_group(conn_id)
        source_ips = np.array(conn['source_ip'])
        if len(source_ips) == 1 and source_ips[0] == my_ip:
            continue

        source_ip = conn['source_ip'].iloc[0]
        timestamps = np.array(conn['timestamp'])
        duration = timestamps[-1] - timestamps[0]

        commands = np.array(conn['command'])
        monero_flags = np.array(conn['monero_flags'])
        timestamps = np.array(conn['timestamp'])
        

        my_ip_mask = (source_ips == my_ip)
        peer_ip_mask = (source_ips != my_ip)
        req_mask = (monero_flags == '1')
        resp_mask = (monero_flags == '2')
        ts_mask = (commands == '1002')

        # check for tcp anomalies
        my_ts_resp_mask = (my_ip_mask & resp_mask & ts_mask)
        peer_ts_req_mask = (peer_ip_mask & req_mask & ts_mask)
        peer_diff = len(commands[my_ts_resp_mask]) - len(commands[peer_ts_req_mask])
        peer_ts_resp_mask = (peer_ip_mask & resp_mask & ts_mask)
        my_ts_req_mask = (my_ip_mask & req_mask & ts_mask)
        my_diff = len(commands[peer_ts_resp_mask]) - len(commands[my_ts_req_mask])
        tcp_anomaly = False
        if peer_diff > 2 or my_diff < -2:
            tcp_anomaly = True

        # calculate timed sync latency
        ts_series = pd.Series(timestamps[peer_ts_req_mask])
        latency = None
        std_dev_lat = None
        var_lat = None
        if not tcp_anomaly and len(ts_series) > 2:
            differences = ts_series.diff().dt.total_seconds().dropna()
            median_lat = differences.median()
            mean_lat = differences.mean()
            std_dev_lat = differences.std()
            var_lat = differences.var()
            latency = min(median_lat, mean_lat)

        # check for Ping flooding
        ping_mask = (commands == '1003')
        peer_ping_mask = (peer_ip_mask & ping_mask)
        ping_series = pd.Series(timestamps[peer_ping_mask])
        ping_frequency = None
        if len(ping_series) > 2:
            differences = ping_series.diff().dt.total_seconds().dropna()
            ping_frequency = max(differences.median(), differences.mean())

        # check for completed handshake
        handshake_mask = (commands == '1001')
        my_handshakes = (handshake_mask & my_ip_mask)
        peer_handshakes = (handshake_mask & peer_ip_mask)
        incomplete_hs = False
        if (len(commands[my_handshakes]) == 0) or (len(commands[peer_handshakes]) == 0):
            incomplete_hs = True

        # average peer list length per connection
        pl_sizes = np.array(conn['peerlist_length'])
        if np.isnan(pl_sizes).all():
            avg_pl_size = None
            total_pl_size = None
            total_pls = None
        else:
            avg_pl_size = np.nanmean(pl_sizes)
            total_pl_size = np.nansum(pl_sizes)
            total_pls = np.sum(~np.isnan(conn['peerlist_length']))

        conn_info.append({
            'connection_id': conn_id,
            'source_ip': source_ip, 
            'tcp_anomaly': tcp_anomaly,
            'initial_command': commands[0],
            'peer_ip': conn['peer_ip'].iloc[0],
            'direction': conn['direction'].iloc[0],
            'duration': duration / pd.Timedelta(seconds=1),
            'total_commands': len(commands),
            'peer_commands': len(commands[peer_ip_mask]),
            'ts_latency': latency,
            'std_dev_latency': std_dev_lat,
            'var_latency': var_lat,
            'total_pings': len(commands[peer_ping_mask]),
            'incomplete_hs': incomplete_hs,
            'ping_frequency': ping_frequency,
            'req_res_diff': peer_diff,                      # my responses minus the peer's requests -> might be higher if wireshark dissector does not catch all requests by the peer
            'res_req_diff': my_diff,                        # peer's responses minus my requests -> might be higher if wireshark dissector does not catch all responses 
            'avg_pl_length': avg_pl_size,
            'total_pl_size': total_pl_size,
            'total_pls': total_pls,
            'time_connection_initiation': timestamps[0]
        })

    conn_df = pd.DataFrame(conn_info)

    conditions = [
        ((conn_df['tcp_anomaly'])),
        ((conn_df['initial_command']=='1003') & (conn_df['total_commands'] == 2)),
        ((conn_df['incomplete_hs'])),
        (conn_df['duration'] < 1),
        (conn_df['duration'] < 10),
        (conn_df['duration'] < 30),
        ((conn_df['total_pings'] > 2)),                                         # ping_flooding
        (conn_df['ts_latency'] > threshold), #conn_df['ts_latency'].quantile(0.95)),         # throttled_ts
        ((conn_df['ts_latency'] < conn_df['ts_latency'].quantile(0.6)) & (conn_df['duration'] > conn_df[conn_df['duration'] > 10]['duration'].quantile(0.5))) # average connection duration
    ]

    choices = [
        'incomplete_tcp',
        'ping_exchange',
        'incomplete_hs',
        'short_lived_1',
        'short_lived_10',
        'short_lived_30',
        'ping_flooding',
        'throttled_ts',
        'standard_average'
    ]

    conn_df['category'] = np.select(conditions, choices, default='standard_other')

    return conn_df
    

def connections(ban, threshold=90):

    ban = ban

    all_conns = pd.DataFrame()

    for node in servers.keys():
        default_port = "18080"
        my_ip = servers[node]

        peer_packets_df = pd.read_parquet(f"data/dataframes/peer_packets_{node}_{ban}.parquet")

        conn_df = analyze_node_connections(peer_packets_df, my_ip, default_port, threshold=threshold)

        all_conns = pd.concat([all_conns, conn_df], ignore_index=True)

    logging.info(f"Connections per IP, median: {conn_df['peer_ip'].value_counts().median()}, mean: {conn_df['peer_ip'].value_counts().mean()}")

    anomalous_categories = ['short_lived_1', 'ping_flooding', 'throttled_ts']
    sus_short = set()
    sus_ping = set()
    sus_ts = set()

    for c in anomalous_categories:
        try: 
            num_connections_of_cat = conn_df['category'].value_counts()[c]
            logging.info(f"Total connections of cat {c}: {num_connections_of_cat}")
            unique_ips_in_cat = conn_df[conn_df['category'] == c]['source_ip'].unique()
            peer_ip_counts = conn_df[conn_df['category'].isin([c])]['peer_ip'].value_counts()
            if c == 'short_lived_1':
                filtered_counts = peer_ip_counts[peer_ip_counts > 10]
                sus_short = filtered_counts.keys()
                logging.info(f"Violation - {c}_ten anomalies found for unique IPs: {len(sus_short)}")
            elif c == 'ping_flooding':
                sus_ping = unique_ips_in_cat
                logging.info(f"Violation - {c} anomalies found for unique IPs: {len(sus_ping)}")
            elif c == 'throttled_ts':
                filtered_counts = peer_ip_counts[peer_ip_counts > 0]
                sus_ts = filtered_counts.keys()
                logging.info(f"Violation - {c} anomalies found for unique IPs: {len(sus_ts)}")
        except KeyError:
            logging.info(f"No Violation - No {c} violation in data set.")

    return sus_short, sus_ping, sus_ts, conn_df['ts_latency']


def ban_and_signature(ban):
    ban = ban

    all_peers_df = pd.DataFrame()

    for node in servers.keys():

        peer_packets_df = pd.read_parquet(f"data/dataframes/peer_packets_{node}_{ban}.parquet")
        #peers_df = pd.read_parquet(f"data/dataframes/peers_{node}_{ban}.parquet")
        
        all_unique_ips = pd.DataFrame({
            #'ip': pd.concat([peer_packets_df['source_ip'], peers_df['ip']]).unique()
            'ip': pd.concat([peer_packets_df['source_ip']]).unique()
        })

        all_peers_df = pd.concat([all_peers_df, all_unique_ips], ignore_index=True)


    all_signature_only_ips = pd.read_csv('results/signature_only_ips.csv', names=['ip'])['ip'].unique()

    signature_only_ips = np.intersect1d(all_signature_only_ips, all_peers_df['ip'].unique())
    ban_list_ips = set()

    with open('data/external/ban_list.txt', 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            if '/' in line:  # CIDR range
                network = ipaddress.ip_network(line)
                ban_list_ips.update(str(ip) for ip in network.hosts())
            else:  # Individual IP
                ban_list_ips.add(line)

    banned_ips = np.intersect1d(list(ban_list_ips), all_peers_df['ip'].unique())

    
    return banned_ips, signature_only_ips