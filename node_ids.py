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

def merge_id_packets(peer_packets_df, my_ip):
    id_packets_df = peer_packets_df[(peer_packets_df['peer_id'].notna())]
    id_packets_df = id_packets_df[id_packets_df['source_ip'] != my_ip]

    return id_packets_df

def detect_ip_id_anomalies(df):
    df_sorted = df.sort_values('timestamp').copy()
    # Track what each IP and ID has been associated with
    ip_history = defaultdict(set)  # IP -> set of IDs it has used
    id_history = defaultdict(set)  # ID -> set of IPs it has used
    
    # current active associations  
    current_ip_to_id = {}  # IP -> current ID
    current_id_to_ip = {}  # ID -> current IP
    
    anomalies = []
    
    for _, row in df_sorted.iterrows():
        ip = row['source_ip']
        peer_id = row['peer_id']
        timestamp = row['timestamp']
        
        # have we seen the IP before?
        if ip in current_ip_to_id:
            # is the ID the same as the current one?
            if current_ip_to_id[ip] != peer_id:
                # IP is switching to a different ID
                # is the IP in the history?
                if peer_id in ip_history[ip]:
                    # Yes -> ANOMALY
                    anomalies.append({
                        'type': 'IP_reused_old_ID',
                        'ip': ip,
                        'peer_id': peer_id,
                        'timestamp': timestamp,
                        'frame_number': row['frame_number']
                    })
                
                # update current mapping
                current_ip_to_id[ip] = peer_id
                ip_history[ip].add(peer_id)
        else:
            # first time seeing this IP
            current_ip_to_id[ip] = peer_id
            ip_history[ip].add(peer_id)
        '''
        # check ID reusing old IP
        if peer_id in current_id_to_ip:
            if current_id_to_ip[peer_id] != ip:
                # ID is switching to a different IP
                if ip in id_history[peer_id]:
                    # ANOMALY
                    anomalies.append({
                        'type': 'ID_reused_old_IP', 
                        'ip': ip,
                        'peer_id': peer_id,
                        'timestamp': timestamp,
                        'frame_number': row['frame_number']
                    })
                
                # Update current mapping
                current_id_to_ip[peer_id] = ip
                id_history[peer_id].add(ip)
        else:
            # First time seeing this ID
            current_id_to_ip[peer_id] = ip
            id_history[peer_id].add(ip)
        '''
    return pd.DataFrame(anomalies)

def find_id_ip_clusters(all_id_packets_df):
    id_by_ip_df = all_id_packets_df.groupby('source_ip').agg({
        'peer_id' : lambda x: x.unique().tolist(),
    }).reset_index()
    id_by_ip_df['count'] = id_by_ip_df['peer_id'].apply(len)

    id_by_ip_df = id_by_ip_df[id_by_ip_df['count'] > 2]

    peer_to_ips = defaultdict(set)
    for _, row in id_by_ip_df.iterrows():
        ip = row['source_ip']
        for peer_id in row['peer_id']:
            peer_to_ips[peer_id].add(ip)

    # Find connected clusters
    clusters = []
    processed_ips = set()

    for ip in id_by_ip_df['source_ip'].unique():
        if ip in processed_ips:
            continue
        
        # BFS to find all connected IPs
        cluster = {ip}
        queue = [ip]
        
        while queue:
            current_ip = queue.pop(0)
            current_peers = id_by_ip_df[id_by_ip_df['source_ip'] == current_ip]['peer_id'].iloc[0]
            
            for peer_id in current_peers:
                for connected_ip in peer_to_ips[peer_id]:
                    if connected_ip not in cluster:
                        cluster.add(connected_ip)
                        queue.append(connected_ip)
        
        clusters.append(cluster)
        processed_ips.update(cluster)

    # Keep only clusters with multiple IPs
    multi_ip_clusters = [cluster for cluster in clusters if len(cluster) > 1]
    logging.info(f"Found {len(multi_ip_clusters)} ID:IP clusters")
    sus_ips = set()
    for i, cluster in enumerate(multi_ip_clusters):
        all_peer_ids = set()
        for ip in cluster:
            ip_peers = id_by_ip_df[id_by_ip_df['source_ip'] == ip]['peer_id'].iloc[0]
            all_peer_ids.update(ip_peers)
        #if len(cluster) > 10 or len(all_peer_ids) > 10:
        sus_ips.update(cluster)
        logging.info(f"ID:IP - Cluster {i+1}: {len(all_peer_ids)} IDs map to {len(cluster)} IPs")
        #print(f"    {list(all_peer_ids)[:10]}")
        #print(f"    {list(cluster)[:10]}")
    return sus_ips, multi_ip_clusters

def node_ids(ban):

    ban = ban

    all_id_packets_df = pd.DataFrame()

    for node in servers.keys():
        default_port = "18080"
        my_ip = servers[node]

        peer_packets_df = pd.read_parquet(f"data/dataframes/peer_packets_{node}_{ban}.parquet")

        id_packets_df = merge_id_packets(peer_packets_df, my_ip)

        all_id_packets_df = pd.concat([all_id_packets_df, id_packets_df], ignore_index=True)

    all_id_packets_df = all_id_packets_df.sort_values('timestamp').copy()
    
    id_anomalies = detect_ip_id_anomalies(all_id_packets_df)

    sus_id_ips, multi_ip_clusters = find_id_ip_clusters(all_id_packets_df)

    return set(sus_id_ips), id_anomalies['ip'].unique()

def node_ids_inv(ban):

    ban = ban

    all_id_packets_df = pd.DataFrame()

    for node in servers.keys():
        default_port = "18080"
        my_ip = servers[node]

        peer_packets_df = pd.read_parquet(f"data/dataframes/peer_packets_{node}_{ban}.parquet")

        id_packets_df = merge_id_packets(peer_packets_df, my_ip)

        all_id_packets_df = pd.concat([all_id_packets_df, id_packets_df], ignore_index=True)

    all_id_packets_df = all_id_packets_df.sort_values('timestamp').copy()
    
    id_anomalies = detect_ip_id_anomalies(all_id_packets_df)

    sus_id_ips, multi_ip_clusters = find_id_ip_clusters(all_id_packets_df)

    return set(sus_id_ips), id_anomalies['ip'].unique(), all_id_packets_df, multi_ip_clusters