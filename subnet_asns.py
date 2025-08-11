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

def ip_to_asn(ip_address, db_path='data/external/GeoLite2-ASN.mmdb'):
    try:
        with maxminddb.open_database(db_path) as reader:
            result = reader.get(ip_address)
            return result['autonomous_system_organization']
    except Exception as e:
        return None

def subnets_asn(ban):
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

    all_unique_ips['subnet'] = all_unique_ips['ip'].apply(lambda ip: str(ipaddress.IPv4Network(f"{ip}/24", strict=False).network_address) + "/24")
    top_subnets = all_unique_ips['subnet'].value_counts().head(15)
    
    plot_data = []
    for subnet in top_subnets.index:
        count = top_subnets[subnet]
        sample_ip = all_unique_ips[all_unique_ips['subnet'] == subnet]['ip'].iloc[0]
        asn = ip_to_asn(sample_ip)
        plot_data.append({'subnet': subnet, 'count': count, 'asn': asn})

    plot_df = pd.DataFrame(plot_data)
    plot_df = plot_df.sort_values('count')

    # Color mapping and plotting
    unique_asns = plot_df['asn'].unique()
    cmap = plt.cm.tab20
    colors = [cmap(i / len(unique_asns)) for i in range(len(unique_asns))]
    asn_color_map = dict(zip(unique_asns, colors))
    bar_colors = [asn_color_map[asn] for asn in plot_df['asn']]

    fig, ax = plt.subplots(figsize=(3.13, 3))
    bars = ax.barh(range(len(plot_df)), plot_df['count'], color=bar_colors)
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

    sus_subnet_ips = set()

    for node in servers.keys():

        peer_packets_df = pd.read_parquet(f"data/dataframes/peer_packets_{node}_{ban}.parquet")
        #peers_df = pd.read_parquet(f"data/dataframes/peers_{node}_{ban}.parquet")
        peer_packets_df['subnet'] = peer_packets_df['source_ip'].apply(lambda ip: str(ipaddress.IPv4Network(f"{ip}/24", strict=False).network_address) + "/24")
        sus_subnet_ips.update(peer_packets_df[peer_packets_df['subnet'].isin(top_subnets.keys())]['source_ip'].unique())

    return set(sus_subnet_ips)

def subnets_asn_ext(ban):
    ban = ban

    all_ips = []
    for node in servers.keys():
        peer_packets_df = pd.read_parquet(f"data/dataframes/peer_packets_{node}_{ban}.parquet")
        peers_df = pd.read_parquet(f"data/dataframes/peers_{node}_{ban}.parquet")
        all_ips.extend(peer_packets_df['source_ip'].tolist())
        all_ips.extend(peers_df['ip'].tolist())

    all_peers_df = pd.DataFrame({'ip': list(set(all_ips))})

    all_peers_df['subnet'] = all_peers_df['ip'].apply(lambda ip: str(ipaddress.IPv4Network(f"{ip}/24", strict=False).network_address) + "/24")
    top_subnets = all_peers_df['subnet'].value_counts().head(15)
    
    plot_data = []
    for subnet in top_subnets.index:
        count = top_subnets[subnet]
        sample_ip = all_peers_df[all_peers_df['subnet'] == subnet]['ip'].iloc[0]
        asn = ip_to_asn(sample_ip)
        plot_data.append({'subnet': subnet, 'count': count, 'asn': asn})

    plot_df = pd.DataFrame(plot_data)
    plot_df = plot_df.sort_values('count')

    # Color mapping and plotting
    unique_asns = plot_df['asn'].unique()
    cmap = plt.cm.tab20
    colors = [cmap(i / len(unique_asns)) for i in range(len(unique_asns))]
    asn_color_map = dict(zip(unique_asns, colors))
    bar_colors = [asn_color_map[asn] for asn in plot_df['asn']]

    fig, ax = plt.subplots(figsize=(3.13, 3))
    bars = ax.barh(range(len(plot_df)), plot_df['count'], color=bar_colors)
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
    plt.savefig(f'results/graphs/{ban}_asn_subnet_dist_ext.pdf', dpi=300)
    plt.show()