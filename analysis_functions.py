import ipaddress
import pandas as pd
import matplotlib.pyplot as plt
from collections import defaultdict
import numpy as np
import maxminddb
from itertools import combinations
from constants import servers
import logging
import os
import random

logging.basicConfig(level=logging.INFO)

# helper functions
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

def set_plt_fallback_format():
    plt.rcParams.update({
        "font.size": 10,
        "axes.titlesize": 10,
        "axes.labelsize": 8,
        "xtick.labelsize": 8,
        "ytick.labelsize": 8,
        "legend.fontsize": 8,
        "figure.titlesize": 10,
        "font.family": "serif"  # Still serif, but no LaTeX
    })

def ip_to_asn(ip_address, db_path='data/external/GeoLite2-ASN.mmdb'):
    try:
        with maxminddb.open_database(db_path) as reader:
            result = reader.get(ip_address)
            return result['autonomous_system_organization']
    except Exception as e:
        return None

# Basic Summary Stats + Syntactic Violations: Support Flags Omission and Last Seen Transmission
def stats_syntactic(ban):
    """Extracts basic information from the combined dataframes, including the syntactic violations.
    General field overview can be found in the logs. 
    Returns:
        list: IP list containing unique IPs omitting the support flags 
        list: IP list containing unique IPs transmitting the last seen timestamp 
        dict: dictionary containing some basic stats about the data 
    """
    ban = ban

    unique_connection_ips = set()
    all_ips = set()
    stats = {
        'totalPackets': 0,
        'totalUniqueIPs': 0,
        'totalUniqueIPsPlusPL': 0,
        'totalPeerLists': 0,
        'sf_packets': 0
    }
    support_flags_sources = set()
    lastseen_sources = set()

    for node in servers.keys():
        
        my_ip = servers[node]

        peer_packets_df = pd.read_parquet(f"data/dataframes/peer_packets_{node}_{ban}.parquet")
        peers_df = pd.read_parquet(f"data/dataframes/peers_{node}_{ban}.parquet")

        unique_connection_ips.update(peer_packets_df['source_ip'].unique())
        all_ips.update(peer_packets_df['source_ip'].unique())
        all_ips.update(peers_df['ip'].unique())

        stats['totalPackets'] += len(peer_packets_df)
        stats['totalPeerLists'] += peers_df[peers_df['source_ip'] != my_ip]['pl_identifier'].nunique()

        # support_flags
        try: 
            support_flags_sources.update(peer_packets_df[(peer_packets_df['command'] == '1001') & (peer_packets_df['support_flags'].isna())]['source_ip'].unique().tolist())
            stats['sf_packets'] += len(peer_packets_df[peer_packets_df['command'] == '1007'])
        except KeyError as e:
            logging.info(f"No Violation - No support_falgs violation for {node}")

        # last_seen timestamp
        try:
            lastseen_sources.update(peers_df[peers_df['last_seen'].notna()]['source_ip'].unique().tolist()) 
        except KeyError as e:
            logging.info(f"No Violation - No last_seen violation for {node}")

        # identify new missing required fields or falsly transmitted field
        logging.info(f"All fields for {node}: {peers_df.keys()}; {peer_packets_df.keys()}")


    stats['totalUniqueIPs'] = len(unique_connection_ips)
    stats['totalUniqueIPsPlusPL'] = len(all_ips)

    logging.info(f"Packets captured: {stats['totalPackets']}")
    logging.info(f"IPs connected to: {stats['totalUniqueIPs']}")
    logging.info(f"IPs collected: {stats['totalUniqueIPsPlusPL']}")


    logging.info(f"Violation - nunique support_flags IPs: {len(support_flags_sources)}")
    logging.info(f"Violation - nunique last_seen IPs: {len(lastseen_sources)}")

    return support_flags_sources, lastseen_sources, stats

# Peer List Diversity
def calc_diversity(ip_list, subnet_list):
    if len(ip_list) < 250:
        return None
    
    unique_subnets = len(set(subnet_list))
    total_ips = len(ip_list)
    
    raw_diversity = unique_subnets / total_ips
    
    return raw_diversity

def calc_node_div(peers_df, my_ip):
    peers_df = peers_df[peers_df['source_ip'] != my_ip].copy()

    peers_df['subnet'] = peers_df['ip'].apply(lambda ip: str(ipaddress.IPv4Network(f"{ip}/24", strict=False).network_address) + "/24")

    pl_by_source = peers_df.groupby('pl_identifier').agg({
        'ip': lambda x: x.tolist(),
        'subnet': lambda x: x.tolist(),
        'source_ip': 'first',
    }).reset_index()

    pl_by_source.columns = ['source_pl', 'peer_ips', 'peer_subnets', 'source_ip']

    pl_by_source['pl_diversity_normalized'] = pl_by_source.apply(
        lambda row: calc_diversity(row['peer_ips'], row['peer_subnets']), axis=1
    )

    pl_by_source = pl_by_source.dropna(subset=['pl_diversity_normalized'])

    pl_by_source['actual_subnets'] = pl_by_source['peer_subnets'].apply(lambda x: len(set(x)))

    return pl_by_source

def peer_list_diversity(ban, threshold=0.1):
    '''Calculate the diversity of each peer list and return IPs below given diversity threshold.
    Returns:
        list: IP list of unique IPs below threshold
        int: maximum announced subnets for the IPs that are below the threshold
        int: median announced subnets for the IPs that are below the threshold
    '''
    ban = ban

    pls_by_source = pd.DataFrame()

    for node in servers.keys():
        default_port = "18080"
        my_ip = servers[node]

        peers_df = pd.read_parquet(f"data/dataframes/peers_{node}_{ban}.parquet")

        node_pl_by_source = calc_node_div(peers_df, my_ip)

        pls_by_source = pd.concat([pls_by_source, node_pl_by_source], ignore_index=True)
    
    threshold = threshold # pl_by_source['pl_diversity_normalized'].quantile(0.05)

    try:
        set_plt_latex_format()
        print("Using LaTeX formatting")
    except:
        set_plt_fallback_format()
        print("LaTeX not available, using fallback formatting")
    plt.figure(figsize=(3.13,1), dpi=300)
    plt.xlabel('Diversity')
    plt.ylabel('Peer List Count')
    plt.hist(pls_by_source['pl_diversity_normalized'], bins=100, log=True, color="red")
    plt.savefig(f'results/graphs/{ban}_loc_pl_diversity.pdf',
               bbox_inches='tight',
               pad_inches=0.1,
               dpi=300)
    #plt.show()
    
    sus_ips = pls_by_source[pls_by_source['pl_diversity_normalized'] < threshold]['source_ip'].unique()
    max_announced_subnets = pls_by_source[pls_by_source['pl_diversity_normalized'] < threshold]['actual_subnets'].max()
    median_announced_subnets = pls_by_source[pls_by_source['pl_diversity_normalized'] < threshold]['actual_subnets'].median()

    # logging
    logging.info(f"PL Diversity - Unique IPs: {len(sus_ips)}")
    logging.info(f"PL Diversity - Max announced subnets: {max_announced_subnets}")
    logging.info(f"PL Diversity - Median announced subnets: {median_announced_subnets}")

    return sus_ips, max_announced_subnets, median_announced_subnets

# Peer List Similarity
def analyze_local_pl_similarity(peers_df, my_ip):
    '''Calculate the pairwise similarity for the given node's dataframe.
    Returns: 
        DataFrame: each row contains the results including source PL identifier and source IPs for both PLs
        '''
    peers_df = peers_df[peers_df['source_ip'] != my_ip].copy()

    peers_df['subnet'] = peers_df['ip'].apply(lambda ip: str(ipaddress.IPv4Network(f"{ip}/24", strict=False).network_address) + "/24")
    #peers_df['asn'] = peers_df['ip'].apply(ip_to_asn)

    pl_by_source = peers_df.groupby('pl_identifier').agg({
        'ip': lambda x: x.tolist(),
        'subnet': lambda x: list(x.unique()),
        #'asn': lambda x: list(x.unique()),
        'source_ip': 'first',
        }).reset_index()
    
    #pl_by_source.columns = ['source_pl', 'peer_ips', 'peer_subnets', 'peer_asns', 'source_ip']
    pl_by_source.columns = ['source_pl', 'peer_ips', 'peer_subnets', 'source_ip']

    pl_by_source['peer_count'] = pl_by_source['peer_ips'].apply(len)
    pl_by_source = pl_by_source[pl_by_source['peer_count'] > 249]

    pl_sets = {row['source_pl']: set(row['peer_ips']) for _, row in pl_by_source.iterrows()}
    
    pl_subnet_sets = {row['source_pl']: set(row['peer_subnets']) for _, row in pl_by_source.iterrows()}

    #pl_asn_sets = {row['source_pl']: set(row['peer_asns']) for _, row in pl_by_source.iterrows()}

    source_ip_lookup = pl_by_source.set_index('source_pl')['source_ip'].to_dict()

    overlaps = []
    for source1, source2 in combinations(pl_sets.keys(), 2):
        ip_1 = source_ip_lookup[source1]
        ip_2 = source_ip_lookup[source2]

        if ip_1 == ip_2:
            continue
       
        ip_intersection = len(pl_sets[source1] & pl_sets[source2])
        ip_union = len(pl_sets[source1] | pl_sets[source2])
        ip_jaccard = ip_intersection / ip_union if ip_union > 0 else 0

        sub_intersection = len(pl_subnet_sets[source1] & pl_subnet_sets[source2])
        sub_union = len(pl_subnet_sets[source1] | pl_subnet_sets[source2])
        sub_jaccard = sub_intersection / sub_union if sub_union > 0 else 0

        #as_intersection = len(pl_asn_sets[source1] & pl_asn_sets[source2])
        #as_union = len(pl_asn_sets[source1] | pl_asn_sets[source2])
        #as_jaccard = as_intersection / as_union if as_union > 0 else 0
    
        overlaps.append({
            'source1': source1, 
            'source2': source2,
            'source1_ip': ip_1,
            'source2_ip': ip_2,
            'ip_intersection': ip_intersection, 
            'ip_jaccard': ip_jaccard,
            'ip_union': ip_union,
            'sub_intersection': sub_intersection, 
            'sub_union': sub_union,
            'sub_jaccard': sub_jaccard,
            #'as_jaccard': as_jaccard
        })
    
    overlap_df = pd.DataFrame(overlaps)

    return overlap_df

def peer_list_similarity(ban, threshold):
    '''Measures the distribution of pairwise similarities in all nodes.
    Returns:
        list: IPs above the given similarity threshold
        DataFrame: combined result dataframe from analyze_local_pl_similarity reduced to IPs above the threshold
    '''
    ban = ban

    all_overlap_df = pd.DataFrame()

    for node in servers.keys():
        default_port = "18080"
        my_ip = servers[node]

        peers_df = pd.read_parquet(f"data/dataframes/peers_{node}_{ban}.parquet")

        overlap_df = analyze_local_pl_similarity(peers_df, my_ip)

        all_overlap_df = pd.concat([all_overlap_df, overlap_df], ignore_index=True)
    

    try:
        set_plt_latex_format()
        print("Using LaTeX formatting")
    except:
        set_plt_fallback_format()
        print("LaTeX not available, using fallback formatting")
    plt.figure(figsize=(3.13,1), dpi=300)
    plt.xlabel('Jaccard Similarity by IP')
    plt.ylabel('Pair Count')
    plt.hist(all_overlap_df['ip_jaccard'], bins=100, range=(0,1), log=True, color='red')
    plt.savefig(f'results/graphs/{ban}_ip_similarity.pdf',
               bbox_inches='tight',
               pad_inches=0.1,
               dpi=300)
    plt.show()

    plt.figure(figsize=(3.13,1), dpi=300)
    plt.ylabel('Pair Count')
    plt.xlabel('Jaccard Similarity by /24 Subnet')
    plt.hist(all_overlap_df['sub_jaccard'], bins=100, range=(0,1), log=True, color='red')
    plt.savefig(f'results/graphs/{ban}_sub_similarity.pdf',
               bbox_inches='tight',
               pad_inches=0.1,
               dpi=300)
    plt.show()

    #plt.figure(figsize=(3.13,1), dpi=300)
    #plt.ylabel('Pair Count')
    #plt.xlabel('Jaccard Similarity across ASs')
    #plt.hist(all_overlap_df['as_jaccard'], bins=100, range=(0,1), log=True, color='red')
    #plt.savefig(f'results/graphs/{ban}_as_similarity.pdf',
    #           bbox_inches='tight',
    #           pad_inches=0.1,
    #           dpi=300)
    #plt.show()

    high_overlap_df = all_overlap_df[all_overlap_df['sub_jaccard']>threshold]

    all_ips = pd.concat([high_overlap_df['source1_ip'], high_overlap_df['source2_ip']])

    ip_counts = all_ips.value_counts()

    frequent_ips = ip_counts[ip_counts > 4].index
    sus_ips = set(frequent_ips)

    # logging
    logging.info(f"PL Similarity - Unique IPs: {len(sus_ips)}")
    
    return sus_ips, high_overlap_df

# ID:IP Anomalies
def merge_id_packets(peer_packets_df, my_ip):
    id_packets_df = peer_packets_df[(peer_packets_df['peer_id'].notna())]
    id_packets_df = id_packets_df[id_packets_df['source_ip'] != my_ip]
    return id_packets_df

def detect_ip_id_anomalies(df):
    '''Detect ID anomalies, where IDs are switched and later switched back to an old one.
    Returns: 
        DataFrame: each row contains an anomaly including: type, ip, peer_id, timestamp
    '''
    df_sorted = df.sort_values('timestamp').copy()
    # Track what each IP and ID has been associated with
    ip_history = defaultdict(set)  # IP -> set of IDs it has used
    
    # current active associations  
    current_ip_to_id = {}  # IP -> current ID
    
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
    return pd.DataFrame(anomalies)

def find_id_ip_clusters(all_id_packets_df):
    '''Clusters IPs based on IDs 
        1. group by IP and filter for IPs announcing multiple IDs
        2. loop over IPs
        3. build ID dict containing all IPs grouped by IDs
        4. BFS to connect all of them
    '''
    id_by_ip_df = all_id_packets_df.groupby('source_ip').agg({
        'peer_id' : lambda x: x.unique().tolist(),
    }).reset_index()
    id_by_ip_df['count'] = id_by_ip_df['peer_id'].apply(len)

    id_count_dist = id_by_ip_df['count']

    # filter IPs that announce more than two IDs
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
    return sus_ips, multi_ip_clusters, id_count_dist

def node_ids(ban):
    '''Detect anomalies within the ID:IP aggregation.
    Returns:
        list: contains unique IPs showing ID anomalies
        list: contains unique IPs clustered in ID:IP 
        list: interestiong of above lists
        list: union of above lists
        list: counts of how many IDs each IP announces 
        int: number of identified clusters
    '''

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

    sus_id_ips, multi_ip_clusters, id_count_dist = find_id_ip_clusters(all_id_packets_df)
    
    if len(id_anomalies) > 0:
        id_anomaly_ips = id_anomalies['ip'].unique()
        intersection_ips = list(set(sus_id_ips).intersection(set(id_anomalies['ip'].unique())))
        union_ips = list(set(sus_id_ips).union(set(id_anomalies['ip'].unique())))
    else:
        id_anomaly_ips = []
        intersection_ips = list(set(sus_id_ips))
        union_ips = list(set(sus_id_ips))

    return set(sus_id_ips), id_anomaly_ips, intersection_ips, union_ips, id_count_dist, len(multi_ip_clusters)

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
    
def analyze_node_connections(peer_packets_df, my_ip, default_port, threshold, min_tss, time_duration=660):
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
        my_ts_series = pd.Series(timestamps[my_ts_req_mask])
        latency = None
        std_dev_lat = None
        var_lat = None
        my_differences = my_ts_series.diff().dt.total_seconds().dropna()
        my_med_lat = my_differences.median()
        my_mean_lat = my_differences.mean()
        my_lat = min(my_med_lat, my_mean_lat)
        second_duration = duration / pd.Timedelta(seconds=1)
        #if not tcp_anomaly and len(ts_series) > min_tss:
        if not tcp_anomaly and second_duration > min_tss and my_lat < 62: 
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

    plot_random_conns(conn_df, grouped, my_ip, time_duration)

    return conn_df

def connections(ban, threshold=90, min_tss=2, time_duration=660):
    ''' Analyze the connections and categorize them along known groups.
    Returns:
        list: Short lived IP addresses
        list: Ping IP addresses
        list: Throttled Timed Sync IP addresses
        list: all latencies
        DataFrame: all connections
    '''
    ban = ban

    all_conns = pd.DataFrame()

    for node in servers.keys():
        default_port = "18080"
        my_ip = servers[node]

        peer_packets_df = pd.read_parquet(f"data/dataframes/peer_packets_{node}_{ban}.parquet")

        conn_df = analyze_node_connections(peer_packets_df, my_ip, default_port, threshold=threshold, min_tss=min_tss, time_duration=time_duration)

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

    return sus_short, sus_ping, sus_ts, conn_df['ts_latency'], all_conns

# PLOT connection anomalies
# RANDOM PLOTS -> currently commented out in analyze_node_connections() just above the return statement
def get_command_category(cmd, flag, source, my_ip):
    """Map commands and flags to categories"""
    if source == my_ip:
        i = 4
    else:
        i = 0
        
    category_map = {
        ('1001', '1'): 1+i,    # Handshake Request
        ('1001', '2'): 1+i,    # HS Resp
        ('1002', '1'): 2+i,    # Timed Sync Request
        ('1002', '2'): 3+i,    # TS Response
        ('1003', '1'): 4+i,    # Ping
        ('1003', '2'): 4+i     # Pong
    }
    
    return category_map.get((cmd, flag), 0)

def setup_axis_appearance(ax, time_duration_seconds, show_ylabel=True):
    """Configure axis appearance for LaTeX paper"""
    category_labels = ['HS', 'TS Req', 'TS Resp', 'Pong', 'HS', 'TS Req', 'TS Resp', 'Ping']

    ax.set_xlabel('Time (s)', fontsize=8)
    #ax.set_ylabel('Command Type', fontsize=10)
    ax.set_xticks(range(0, time_duration_seconds + 1, 120))
    ax.set_yticks([1, 2, 3, 4, 5, 6, 7, 8])
    ax.set_yticklabels(category_labels, fontsize=8)
    ax.tick_params(axis='both', which='major', labelsize=8)
    ax.set_ylim(0.5, 8.5)
    
    ax.set_xlim(0, time_duration_seconds)
    ax.grid(True, alpha=0.3, linestyle='--')
    
    # Add minor grid lines at 60s intervals
    ax.set_xticks(range(0, time_duration_seconds, 60), minor=True)
    ax.grid(True, alpha=0.3, linestyle='--', which='minor')

def plot_command_timeline_subplot(ax, base_commands, base_flags, base_series, base_sources, title, my_ip,
                                time_duration_seconds=300, show_ylabel=True):
    """Plot command timeline on given axis"""
    if len(base_series) == 0:
        ax.text(0.5, 0.5, 'No data', transform=ax.transAxes, 
                ha='center', va='center', fontsize=7)
        ax.set_title(title, fontsize=8, pad=8)

        setup_axis_appearance(ax, time_duration_seconds, show_ylabel)
        return
    
    # Convert to seconds from start and filter by duration
    time_seconds = (base_series - base_series.iloc[0]).dt.total_seconds()
    time_mask = time_seconds <= time_duration_seconds
    
    if not time_mask.any():
        ax.text(0.5, 0.5, 'No data in time range', transform=ax.transAxes, 
                ha='center', va='center', fontsize=9)
        ax.set_title(title, fontsize=10, pad=10)
        setup_axis_appearance(ax, time_duration_seconds, show_ylabel)
        return
    
    # Filter data and create categories    
    commands_filtered = base_commands[time_mask]
    flags_filtered = base_flags[time_mask]
    time_filtered = time_seconds[time_mask]
    sources_filtered = base_sources[time_mask]

    
    categories = [get_command_category(cmd, flag, source, my_ip) 
                  for cmd, flag, source in zip(commands_filtered, flags_filtered, sources_filtered)]
    
    #print(f"{title}: {sources_filtered[:2]} : {base_series[:1]}")
    
    colors = ['red' if source == my_ip else 'blue' 
          for source in sources_filtered]

    ax.scatter(time_filtered, categories, c=colors, s=10, alpha=0.7)

    ax.axhline(4.5, color='gray', linestyle=':')

    ax.text(time_duration_seconds * 0.95, 4.7, 'Measurement Node', 
            ha='right', va='bottom', fontsize=8, color='red')
    
    # Add text below the line  
    ax.text(time_duration_seconds * 0.95, 4.3, 'Peer', 
            ha='right', va='top', fontsize=8, color='blue')
    
    #ax.set_title(title, fontsize=10, pad=10, weight='bold')
    if sources_filtered[0] == my_ip:
        direction = 'outgoing'
    else: 
        direction = 'incoming'
    setup_axis_appearance(ax, time_duration_seconds, show_ylabel)
    
def plot_random_conns(conn_df, grouped, my_ip, time_duration):
    set_plt_latex_format()
    categories_to_plot = ['throttled_ts']#['ping_flooding', 'throttled_ts', 'standard_average']  # Modify this array as needed
    max_connections_per_type = 5
    time_duration_seconds=time_duration

    # Add randomness to peer selection
    connection_data = {}
    used_peers = set()

    for category in categories_to_plot:
            
        category_df = conn_df[conn_df['category'] == category]
        
        # Randomly shuffle the connections in this category
        category_df = category_df.sample(frac=1, random_state=random.randint(1, 10000))
        
        connection_data[category] = []
        count = 0
        
        for idx, row in category_df.iterrows():
            if count >= max_connections_per_type:
                break
                
            conn_id = row['connection_id']
            peer_ip = row['peer_ip']

            if peer_ip in used_peers:
                continue
                
            conn = grouped.get_group(conn_id)
            
            commands = np.array(conn['command'])
            monero_flags = np.array(conn['monero_flags'])
            timestamps = np.array(conn['timestamp'])
            source_ips = np.array(conn['source_ip'])
                
            used_peers.add(peer_ip)
            
            # base commands only interesting as only these are expectable
            base_mask = np.isin(commands, ['1001', '1002', '1003'])
            base_series = pd.Series(timestamps[base_mask])
            
            connection_data[category].append({
                'peer': peer_ip,
                'source_ips': source_ips[base_mask],
                'commands': commands[base_mask],
                'flags': monero_flags[base_mask],
                'series': base_series
            })
            count += 1

    # individual plots for each category
    for category in connection_data:
        for j, data in enumerate(connection_data[category]):
            fig, ax = plt.subplots(figsize=(3.13, 1))
            
            title = f"{category}_{j+1}\n{data['peer']}-{data['series'].iloc[0]}"
            
            plot_command_timeline_subplot(
                ax, data['commands'], data['flags'], 
                data['series'], data['source_ips'], title, my_ip,
                time_duration_seconds, show_ylabel=True
            )
            
            #plt.tight_layout()
            plt.savefig(f'results/graphs/{category}_{j+1}.pdf', bbox_inches='tight', dpi=300)
            plt.show()
            #plt.close()

# Ban and Signature-only IPs
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

# Subnets and ASNs
def subnets_asn_comb(ban):
    ban = ban

    all_peers_df = pd.DataFrame()
    all_peers_extended_df = pd.DataFrame()  # New: for combined data
    high_subnet_ips = set()
    lion_peers = set()

    for node in servers.keys():
        peer_packets_df = pd.read_parquet(f"data/dataframes/peer_packets_{node}_{ban}.parquet")
        peers_df = pd.read_parquet(f"data/dataframes/peers_{node}_{ban}.parquet")
        
        # Add subnet and ASN columns once
        peer_packets_df['subnet'] = peer_packets_df['source_ip'].apply(lambda ip: str(ipaddress.IPv4Network(f"{ip}/24", strict=False).network_address) + "/24")
        #peer_packets_df['asn'] = peer_packets_df['source_ip'].apply(ip_to_asn)
        
        # Original data (peer_packets only)
        all_unique_ips = pd.DataFrame({
            'ip': peer_packets_df['source_ip'].unique()
        })
        all_peers_df = pd.concat([all_peers_df, all_unique_ips], ignore_index=True)
        
        # Extended data (peer_packets + peers)
        all_unique_ips_ext = pd.DataFrame({
            'ip': pd.concat([peer_packets_df['source_ip'], peers_df['ip']]).unique()
        })
        all_peers_extended_df = pd.concat([all_peers_extended_df, all_unique_ips_ext], ignore_index=True)
        
        all_peers_extended_df['asn'] = all_peers_extended_df['ip'].apply(ip_to_asn)

        # Collect lion_peers data in the same loop (ASN already calculated)
        lion_peers.update(all_peers_extended_df[all_peers_extended_df['asn'] == 'LIONLINK-NETWORKS']['ip'].unique())

    # Remove duplicates across nodes
    all_peers_df = all_peers_df.drop_duplicates(subset=['ip'])
    all_peers_extended_df = all_peers_extended_df.drop_duplicates(subset=['ip'])

    # Process original data (for main bars)
    all_peers_df['subnet'] = all_peers_df['ip'].apply(lambda ip: str(ipaddress.IPv4Network(f"{ip}/24", strict=False).network_address) + "/24")
    median_subnet_peers = all_peers_df['subnet'].value_counts().quantile(0.5)
    top_subnets = all_peers_df['subnet'].value_counts().head(15)
    
    # Process extended data (for background bars)
    all_peers_extended_df['subnet'] = all_peers_extended_df['ip'].apply(lambda ip: str(ipaddress.IPv4Network(f"{ip}/24", strict=False).network_address) + "/24")
    extended_subnet_counts = all_peers_extended_df['subnet'].value_counts()
    
    # Now collect high_subnet_ips using already-processed data
    for node in servers.keys():
        peer_packets_df = pd.read_parquet(f"data/dataframes/peer_packets_{node}_{ban}.parquet")
        peer_packets_df['subnet'] = peer_packets_df['source_ip'].apply(lambda ip: str(ipaddress.IPv4Network(f"{ip}/24", strict=False).network_address) + "/24")
        high_subnet_ips.update(peer_packets_df[peer_packets_df['subnet'].isin(top_subnets.index)]['source_ip'].unique())
    
    plot_data = []
    for subnet in top_subnets.index:
        count_original = top_subnets[subnet]
        count_extended = extended_subnet_counts.get(subnet, count_original)  # Get extended count or fall back to original
        sample_ip = all_peers_df[all_peers_df['subnet'] == subnet]['ip'].iloc[0]
        asn = ip_to_asn(sample_ip)
        plot_data.append({
            'subnet': subnet, 
            'count_original': count_original,
            'count_extended': count_extended,
            'asn': asn
        })

    plot_df = pd.DataFrame(plot_data)
    plot_df = plot_df.sort_values('count_original')  # Sort by original counts

    # Color mapping
    unique_asns = plot_df['asn'].unique()
    cmap = plt.cm.tab20
    colors = [cmap(i / len(unique_asns)) for i in range(len(unique_asns))]
    asn_color_map = dict(zip(unique_asns, colors))
    bar_colors = [asn_color_map[asn] for asn in plot_df['asn']]

    fig, ax = plt.subplots(figsize=(3.13, 3))
    
    # Plot background bars (extended data) in light gray
    bars_bg = ax.barh(range(len(plot_df)), plot_df['count_extended'], 
                      color='lightgray', alpha=0.8, zorder=1)
    
    # Plot main bars (original data) with ASN colors
    bars = ax.barh(range(len(plot_df)), plot_df['count_original'], 
                   color=bar_colors, zorder=2)
    
    ax.set_yticks(range(len(plot_df)))
    ax.set_yticklabels([subnet.split('/')[0] for subnet in plot_df['subnet']], rotation=45, fontsize=8)

    def clean_asn_name(asn):
        return str(asn).replace('&', 'and').replace('_', ' ')

    for i, (bar, asn) in enumerate(zip(bars, plot_df['asn'])):
        clean_asn = clean_asn_name(asn)
        ax.text(10, (bar.get_y() + bar.get_height()/2)-0.1,
                f'{clean_asn}', ha='left', va='center', fontsize=8, alpha=0.8)

    ax.set_xlabel('Count')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_linewidth(0.5)
    ax.spines['bottom'].set_linewidth(0.5)
    plt.tight_layout()
    plt.savefig(f'results/graphs/{ban}_asn_subnet_dist_conns.pdf', dpi=300)
    plt.show()

    return set(high_subnet_ips), len(lion_peers), median_subnet_peers

# In-Degree Analysis
def indegree(ban):
    ban = ban
    
    all_mentions = []

    for node in servers.keys():
        #peer_packets_df = pd.read_parquet(f"data/dataframes/peer_packets_{node}_{ban}.parquet")
        peers_df = pd.read_parquet(f"data/dataframes/peers_{node}_{ban}.parquet")

        peers_df = peers_df[peers_df['source_ip'] != servers[node]]

        all_mentions.extend(peers_df['ip'])
    
    return all_mentions

##############################################
############ Final Evaluation ################
##############################################

# Overlap Plot and unique total non-standard peers
def summarize_IPs_plot_overlap(ban, data_dict):
    ban=ban
    
    keys = list(data_dict.keys())
    n = len(keys)
    matrix = np.zeros((n, n))
    matrix_asn = np.zeros((n, n))
    
    for i, key1 in enumerate(keys):
        for j, key2 in enumerate(keys):
            overlap = len(set(data_dict[key1]['ips']) & set(data_dict[key2]['ips']))
            overlap_asn = len(set(data_dict[key1]['asns']) & set(data_dict[key2]['asns']))
            matrix[i, j] = overlap
            matrix_asn[i, j] = overlap_asn
    
    # Normalize both matrices 
    matrix_norm = matrix / matrix.max() if matrix.max() > 0 else matrix
    matrix_asn_norm = matrix_asn / matrix_asn.max() if matrix_asn.max() > 0 else matrix_asn
    
    # Create combined matrix using the maximum normalized value
    combined_matrix = np.maximum(matrix_norm, matrix_asn_norm)
    
    new_labels = ['SFO', 'LST', 'PLD', 'PLS', 'ID', 'SlC', 'Ping', 'TS', 'Sig', 'Sub', 'Ban']
    #new_labels = ['SFO', 'LST', 'PLD', 'PLS', 'ID', 'SlC', 'Ping', 'TS', 'Sig', 'Ban']

    plt.figure(figsize=(3.13, 4.2), dpi=300)
    plt.imshow(combined_matrix, cmap='Blues')
    plt.xticks(range(n), new_labels, rotation=45, fontsize=6)
    plt.yticks(range(n), new_labels, fontsize=6)
    
    # Add values to cells with dynamic color based on combined intensity
    for i in range(n):
        for j in range(n):
            ip_val = int(matrix[i, j])
            asn_val = int(matrix_asn[i, j])
            
            # Use combined matrix for text color decision
            if combined_matrix[i, j] > 0.67:  # Top third of combined scale
                color = 'white'
            else:
                color = 'black'
                
            plt.text(j, i-0.2, ip_val, ha='center', va='center', fontsize=5, color=color)
            plt.text(j, i+0.2, f"({asn_val})", ha='center', va='center', fontsize=4, color=color)
    
    legend_text1 = "SFO=Support Flags Omission, LST=Last Seen Transmission, PLD=Peer List Diversity"
    legend_text2 = "PLS=Peer List Similarity, ID=Node ID Anomaly, SlC=Short-lived Connections"
    legend_text3 = "Ping=Ping Flooding, TS=Timed Sync Throttling, Sig=Signature Only TCP Packets"
    legend_text4 = "Sub=High Subnet Saturation, Ban=Community Ban Listed"
    legend_text1 = "Support Flags Omission, Last Seen Transmission, Peer List Diversity,"
    legend_text2 = "Peer List Similarity, Node ID Anomaly, Short-lived Connections,"
    legend_text3 = "Ping Flooding, Timed Sync Throttling, Signature Only TCP Packets,"
    legend_text4 = "High Subnet Saturation, Community Ban Listed"

    plt.subplots_adjust(bottom=0.25)

    plt.figtext(0.5, 0.14, legend_text1, ha='center', fontsize=6)
    plt.figtext(0.5, 0.11, legend_text2, ha='center', fontsize=6)
    plt.figtext(0.5, 0.08, legend_text3, ha='center', fontsize=6)
    plt.figtext(0.5, 0.05, legend_text4, ha='center', fontsize=6)

    plt.tight_layout()
    plt.savefig(f'results/graphs/{ban}_overlap_ips_as.pdf', bbox_inches='tight')
    plt.show()

    identified_ns_peers = set()
    for key in data_dict.keys():
        if not key in ['High Subnet Sat', 'Ban Listed']:
            for ip in data_dict[key]['ips']:
                identified_ns_peers.add(ip)
    logging.info(f"Identified {len(identified_ns_peers)} non-standard peers.")
    return identified_ns_peers

# Measure and plot the saturation of non-standard peers
def get_conns(peer_packets_df, my_ip, default_port):
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

        conn_info.append({
            'connection_id': conn_id,
            'source_ip': source_ip, 
            'peer_ip': conn['peer_ip'].iloc[0],
            'direction': conn['direction'].iloc[0],
            'duration': duration / pd.Timedelta(seconds=1)
        })

    conn_df = pd.DataFrame(conn_info)

    return conn_df, grouped

def average_time_series(series_list):
    if not series_list:
        return pd.DataFrame()
    
    # align to common time values
    all_times = pd.Index([])
    for series in series_list:
        all_times = all_times.union(series.index)
    
    # reindex and missing 0
    aligned_series = []
    for series in series_list:
        aligned = series.reindex(all_times).fillna(method='ffill').fillna(0)
        aligned_series.append(aligned)
    
    # mean across nodes
    return sum(aligned_series) / len(aligned_series)

def plot_anom_saturation(ban, total_anomaly_set):
    
    incoming_series = []
    outgoing_series = []


    for node in servers.keys():
        default_port = "18080"
        my_ip = servers[node]

        peer_packets_df = pd.read_parquet(f"data/dataframes/peer_packets_{node}_{ban}.parquet")
        conn_df, grouped = get_conns(peer_packets_df, my_ip, default_port)

        events = []
        for idx, row in conn_df.iterrows():
            conn_id = row['connection_id']
            conn = grouped.get_group(conn_id)
            timestamps = conn['timestamp']
            
            start_time = timestamps.iloc[0]
            end_time = timestamps.iloc[-1]
            direction = row['direction']

            if row['peer_ip'] in total_anomaly_set:
                conn_type = 'anomalous'
            else:
                conn_type = 'non-anomalous'
            
            events.append({'time': start_time, 'direction': direction, 'classification': conn_type, 'change': 1})
            events.append({'time': end_time, 'direction': direction, 'classification': conn_type, 'change': -1})

        events_df = pd.DataFrame(events)
        events_df = events_df.sort_values('time').set_index('time')


        for direction in ['incoming', 'outgoing']:
            direction_events = events_df[events_df['direction'] == direction]
            if not direction_events.empty:
                pivot = direction_events.pivot_table(
                    index='time', columns='classification', values='change',
                    aggfunc='sum', fill_value=0
                )
                resampled = pivot.resample('1s').sum().fillna(0)
                cumulative = resampled.cumsum().clip(lower=0)
                
                if direction == 'incoming':
                    incoming_series.append(cumulative)
                else:
                    outgoing_series.append(cumulative)


        del peer_packets_df, conn_df 
    
    avg_incoming = average_time_series(incoming_series)
    avg_outgoing = average_time_series(outgoing_series)

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(3.13, 3), dpi=300)

    classifications = avg_incoming.columns if not avg_incoming.empty else avg_outgoing.columns
    # colors = plt.cm.Accent(np.linspace(0, 1, len(classifications)))
    color_map = {
        'anomalous': 'red',
        'non-anomalous': 'gray'
    }

    stats = {}
    # plot averaged data
    for cumulative, ax, title in [(avg_incoming, ax1, 'In'), (avg_outgoing, ax2, 'Out')]:
        if not cumulative.empty:
            ax.stackplot(cumulative.index,
                        *[cumulative[cls] for cls in cumulative.columns],
                        labels=cumulative.columns,
                        colors=[color_map[cls] for cls in cumulative.columns],
                        alpha=0.7)
            ax.set_ylabel(f'{title} Connections (Avg)')
            ax.legend(loc='upper right')
            ax.xaxis.set_major_locator(plt.MaxNLocator(nbins=2))
        
        # Calculate proportions
        total_active = cumulative.sum(axis=1)
        # Only consider time points where connections exist
        mask = total_active > 0
        proportions = cumulative[mask].div(total_active[mask], axis=0)
        average_proportions = proportions.mean()
        mean_anomalous_active = cumulative[mask]['anomalous'].mean()

        stats[f'{title}_mean_anomalous_active'] = mean_anomalous_active
    
        logging.info(f"Averaged absolute active anomalous connections: {mean_anomalous_active:.3f}")
        for conn_type, prop in average_proportions.items():
            stats[f'{title}_{conn_type}_prop'] = prop * 100
            logging.info(f"  {conn_type}: {prop:.3f}")

    ax2.set_xlabel('Time')
    plt.tight_layout()
    plt.savefig(f'results/graphs/{ban}_conn_saturation_averaged.pdf')
    plt.show()

    return stats

# Check which of the peers are reachable (or have been reached by us)
def reachable(ban, identified_ns_peers):
    ban = ban

    reachable_peers = set()

    for node in servers.keys():
        peer_packets_df = pd.read_parquet(f"data/dataframes/peer_packets_{node}_{ban}.parquet")

        mask = (peer_packets_df['source_ip'].isin(identified_ns_peers)) & (peer_packets_df['dst_port'] == '18080')

        reachable_peers.update(peer_packets_df.loc[mask, 'source_ip'].unique())

        del peer_packets_df

    return reachable_peers 

# Compare our identified peers with ban list
def compare_to_banlist(identified_ns_peers):
    stats = {}
    banned_ips = set()
    with open('data/external/ban_list.txt', 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            if '/' in line:  # CIDR range
                network = ipaddress.ip_network(line)
                banned_ips.update(str(ip) for ip in network.hosts())
            else:  # Individual IP
                banned_ips.add(line)

    logging.info(f"My ban list: {len(identified_ns_peers)} - community ban list: {len(banned_ips)}")

    stats['common_ips'] = identified_ns_peers & banned_ips
    logging.info(f"    common IPs: {len(stats['common_ips'])}")

    stats['all_ips'] = identified_ns_peers | banned_ips
    logging.info(f"    {len(stats['all_ips'])}")

    stats['my_unique'] = identified_ns_peers - banned_ips
    logging.info(f"    uniquely identified: {len(stats['my_unique'])}")

    return stats

# Calculate Peer List poisoning
def calc_poison_prop(peers_df, ns_subnets):

    peers_df['subnet'] = peers_df['ip'].apply(lambda ip: str(ipaddress.IPv4Network(f"{ip}/24", strict=False).network_address) + "/24")

    pl_by_source_ip = peers_df.groupby('source_ip').agg({
        'ip': lambda x: x.tolist(),
        'subnet': lambda x: x.tolist(),
    }).reset_index()

    pl_by_source_ip.columns = ['source_ip', 'peer_ips', 'peer_subnets']

    portions = []

    for _, row in pl_by_source_ip.iterrows():
        if len(set(row['peer_ips'])) < 250:
            continue
        overlap = len(set(row['peer_subnets']) & set(ns_subnets))
        promotions = len(set(row['peer_subnets']))

        portion = overlap/promotions

        portions.append(portion)

    return portions

def pl_poison_dist(ban, identified_ns_peers):
    ban = ban

    ns_subnets = set()

    for ip in identified_ns_peers:
        ns_subnets.add(str(ipaddress.IPv4Network(f"{ip}/24", strict=False).network_address) + "/24")

    all_portions = []

    for node in servers.keys():

        #peer_packets_df = pd.read_parquet(f"data/dataframes/peer_packets_{node}_{ban}.parquet")
        peers_df = pd.read_parquet(f"data/dataframes/peers_{node}_{ban}.parquet")

        all_portions.extend(calc_poison_prop(peers_df, ns_subnets))
    
    return all_portions

# LaTex result writing
def format_number(value):
   # Convert to float if it's a number
   if isinstance(value, (int, float)):
       # Round to 3 decimal places
       rounded = round(float(value), 2)
       
       # Check if it's effectively a whole number
       if rounded == int(rounded):
           # Format as integer with commas if >= 1000
           if abs(rounded) >= 1000:
               return f"{int(rounded):,}"
           else:
               return str(int(rounded))
       else:
           # Format with decimal places and commas if >= 1000
           if abs(rounded) >= 1000:
               return f"{rounded:,.2f}"
           else:
               return f"{rounded:.2f}"
   
   # Return as-is if not a number
   return str(value)

def write_tex(results, no_space):
    with open('results.tex', 'w') as f:
        for cmd_name, value in results.items():
            formatted_value = format_number(value)
            if cmd_name in no_space:
                f.write(f"\\newcommand{{\\{cmd_name}}}{{{formatted_value}}}\n")
            else:
                f.write(f"\\newcommand{{\\{cmd_name}}}{{{formatted_value} }}\n")
    
def retrieve_asns(ips): 
    tmp_asns = set()
    for ip in ips:
        tmp_asns.add(ip_to_asn(ip))
    return tmp_asns

def format_and_write_tex(ban, basic_stats, anomaly_dict, conn_df, all_latencies, indegrees, 
                         sus_id_anomaly_ips, sus_id_cluster_ips, num_clusters, median_subnet_peers, 
                         identified_ns_peers, reachable_peers, lion_peers, saturation_stats, 
                         ban_list_stats, pl_poison, len_all_ns_peers):
    
    no_space = ['medianSubnetPeers', 'medConnCommands', 'medConnDuration', 'avgInDegree', 'medianInDegree',
                'incomingConnSatwithout', 'outgoingConnSatwithout', 'percentageAnomNet', 'avgPeerPoisoning',
                'outgoingConnSatwith', 'incomingConnSatwith','percentageAnomReach']

    two_decimal = ['percentageAnomNet']

    results = {
        'totalPackets': basic_stats['totalPackets'],
        'totalUniqueIPs': basic_stats['totalUniqueIPs'],
        'totalUniqueIPsPlusPL': basic_stats['totalUniqueIPsPlusPL'],
        'totalPeerLists': basic_stats['totalPeerLists'],
        'totalUniqueIPssupportflag': len(anomaly_dict['SF Omission']['ips']), 
        'UniqueASNsSupportFlag' : len(anomaly_dict['SF Omission']['asns']),
        'SFRpackets': basic_stats['sf_packets'],
        'totalUniqueIPslastseen': len(anomaly_dict['LS Transmission']['ips']),
        'UniqueASNsLastSeen': len(anomaly_dict['LS Transmission']['asns']),
        'totalUniqueIPsPLDiv': len(anomaly_dict['PL Diversity']['ips']),
        'UniqueASNsPLDiv': len(anomaly_dict['PL Diversity']['asns']),
        'totalUniqueIPsPLSim': len(anomaly_dict['PL Similarity']['ips']),
        'UniqueASNsPLSim': len(anomaly_dict['PL Similarity']['asns']),
        'totalConnections': (len(conn_df) - len(conn_df[conn_df['category'].isin(['ping_sequence'])])), # Ping sequences are test sequences on different ports, not really individual connections but appearing as such
        'tcpAnomaliesIncHS': len(conn_df[conn_df['category'].isin(['incomplete_tcp','incomplete_hs'])]),
        'avgConnDuration': conn_df['duration'].mean(),
        'medConnDuration': conn_df['duration'].median(),
        'avgConnCommands': conn_df['total_commands'].mean(),
        'medConnCommands': conn_df['total_commands'].median(),
        'shortLivedConnsOne': len(conn_df[conn_df['category'] == 'short_lived_1']),
        'totalUniqueIPsShortTwo': len(anomaly_dict['Short-lived Conn']['ips']),
        'UniqueASNsShortTwo': len(anomaly_dict['Short-lived Conn']['asns']),
        'shortLivedOneMaxIP': int(conn_df[conn_df['category'] == 'short_lived_1']['source_ip'].value_counts().max()),
        'throttledTSmedianfreq': all_latencies.quantile(0.5),
        'throttledTSConns': len(conn_df[conn_df['category'] == 'throttled_ts']),
        'uniqueIPsthrottledTS': len(anomaly_dict['Throttled TS']['ips']),
        'UniqueASNsthrottledTS': len(anomaly_dict['Throttled TS']['asns']),
        'pingFloodingConns': len(conn_df[conn_df['category'] == 'ping_flooding']),
        'pingFloodingIPs': len(anomaly_dict['Ping Flooding']['ips']),
        'pingFloodingASNs': len(anomaly_dict['Ping Flooding']['asns']),
        'avgInDegree': indegrees.value_counts().mean(),
        'medianInDegree': indegrees.value_counts().median(),
        'uniqueIPsIDAnom': len(sus_id_anomaly_ips),
        'uniqueASIDAnom': len(retrieve_asns(sus_id_anomaly_ips)),
        'uniqueIDclusterIPs': len(sus_id_cluster_ips),
        'uniqueIDclusterASs': len(retrieve_asns(sus_id_cluster_ips)),
        'numIDcluster': num_clusters,
        'uniqueIDIPinterIPs': len(anomaly_dict['ID:IP Anomaly']['ips']),
        'uniqueIDIPinterASNs': len(anomaly_dict['ID:IP Anomaly']['asns']),
        'medianSubnetPeers': median_subnet_peers,
        'totalSusPeers': len(identified_ns_peers),
        'susAndReachable': len(reachable_peers),
        'totalUniqueIPsSign': len(anomaly_dict['Signature Only']['ips']),
        'UniqueASNsSign': len(anomaly_dict['Signature Only']['asns']),
        'LionLinkPeers': lion_peers,
        f'incomingConnSat{ban}': saturation_stats['In_anomalous_prop'],
        f'outgoingConnSat{ban}': saturation_stats['Out_anomalous_prop'],
        f'totalincomingConnSat{ban}': saturation_stats['In_mean_anomalous_active'],
        f'totaloutgoingConnSat{ban}': saturation_stats['Out_mean_anomalous_active'],
        'avgPeerPoisoning': (np.mean(pl_poison)*100),
        'percentageAnomNet': (len(identified_ns_peers)/basic_stats['totalUniqueIPs']*100),
        'percentageAnomReach': (len(reachable_peers)/basic_stats['totalUniqueIPs']*100),
        'totalAnomalous': len_all_ns_peers,
        'myUniquensPeers': len(ban_list_stats['my_unique'])
    }

    write_tex(results, no_space)

def save_ns_peers(identified_ns_peers):
    existing_ips = set()
    if os.path.exists('results/identified_ns_ips.txt'):
        with open('results/identified_ns_ips.txt', 'r') as file:
            existing_ips = set(line.strip() for line in file)
    
    logging.info(f"Identified before: {len(existing_ips)} non-standard peers.")
    
    new_ips = [ip for ip in identified_ns_peers if ip not in existing_ips]
    if new_ips:
        with open('results/identified_ns_ips.txt', 'a') as file:
            file.write('\n'.join(new_ips) + '\n')
    
    existing_ips.update(identified_ns_peers)
    logging.info(f"Identified in all runs: {len(existing_ips)} non-standard peers.")
    
    return existing_ips 
