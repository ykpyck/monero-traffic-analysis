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



def basic_evident(ban):

    ban = ban

    unique_connection_ips = set()
    all_ips = set()
    stats = {
        'totalPackets': 0,
        'totalUniqueIPs': 0,
        'totalUniqueIPsPlusPL': 0,
        'totalPeerLists': 0
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
        except KeyError as e:
            logging.info(f"No Violation - No support_falgs violation for {node}")

        # last_seen timestamp
        try:
            lastseen_sources.update(peers_df[peers_df['last_seen'].notna()]['source_ip'].unique().tolist()) 
        except KeyError as e:
            logging.info(f"No Violation - No last_seen violation for {node}")


    stats['totalUniqueIPs'] = len(unique_connection_ips)
    stats['totalUniqueIPsPlusPL'] = len(all_ips)

    logging.info(f"Packets captured: {stats['totalPackets']}")
    logging.info(f"IPs connected to: {stats['totalUniqueIPs']}")
    logging.info(f"IPs collected: {stats['totalUniqueIPsPlusPL']}")


    logging.info(f"Violation - nunique support_flags IPs: {len(support_flags_sources)}")
    logging.info(f"Violation - nunique last_seen IPs: {len(lastseen_sources)}")

    return support_flags_sources, lastseen_sources, stats