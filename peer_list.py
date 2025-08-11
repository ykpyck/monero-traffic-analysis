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

def ip_to_asn(ip_address, db_path='data/external/GeoLite2-ASN.mmdb'):
    try:
        with maxminddb.open_database(db_path) as reader:
            result = reader.get(ip_address)
            return result['autonomous_system_organization']
    except Exception as e:
        return None
    

def peer_list_diversity(ban, threshold=0.1):

    ban = ban

    pls_by_source = pd.DataFrame()

    for node in servers.keys():
        default_port = "18080"
        my_ip = servers[node]

        peers_df = pd.read_parquet(f"data/dataframes/peers_{node}_{ban}.parquet")

        node_pl_by_source = calc_node_div(peers_df, my_ip)

        pls_by_source = pd.concat([pls_by_source, node_pl_by_source], ignore_index=True)
    
    threshold = threshold # pl_by_source['pl_diversity_normalized'].quantile(0.05)

    set_plt_latex_format()
    plt.figure(figsize=(3.13,1), dpi=300)
    plt.xlabel('Diversity')
    plt.ylabel('Peer List Count')
    plt.hist(pls_by_source['pl_diversity_normalized'], bins=100, log=True, color="red")
    plt.savefig(f'results/graphs/{ban}_loc_pl_diversity.pdf',
               bbox_inches='tight',
               pad_inches=0.1,
               dpi=300)
    plt.show()
    
    sus_ips = pls_by_source[pls_by_source['pl_diversity_normalized'] < threshold]['source_ip'].unique()
    max_announced_subnets = pls_by_source[pls_by_source['pl_diversity_normalized'] < threshold]['actual_subnets'].max()
    median_announced_subnets = pls_by_source[pls_by_source['pl_diversity_normalized'] < threshold]['actual_subnets'].median()

    # logging
    logging.info(f"")
    logging.info(f"PL Diversity - Unique IPs: {len(sus_ips)}")
    logging.info(f"PL Diversity - Max announced subnets: {max_announced_subnets}")
    logging.info(f"PL Diversity - Median announced subnets: {median_announced_subnets}")

    return sus_ips, max_announced_subnets, median_announced_subnets

def analyze_local_pl_similarity(peers_df, my_ip):
    peers_df = peers_df[peers_df['source_ip'] != my_ip].copy()

    peers_df['subnet'] = peers_df['ip'].apply(lambda ip: str(ipaddress.IPv4Network(f"{ip}/24", strict=False).network_address) + "/24")
    peers_df['asn'] = peers_df['ip'].apply(ip_to_asn)

    pl_by_source = peers_df.groupby('pl_identifier').agg({
        'ip': lambda x: x.tolist(),
        'subnet': lambda x: list(x.unique()),
        'asn': lambda x: list(x.unique()),
        'source_ip': 'first',
        }).reset_index()
    
    pl_by_source.columns = ['source_pl', 'peer_ips', 'peer_subnets', 'peer_asns', 'source_ip']
    #print(unique_peers_by_source.head())

    pl_by_source['peer_count'] = pl_by_source['peer_ips'].apply(len)
    pl_by_source = pl_by_source[pl_by_source['peer_count'] > 249]

    pl_sets = {row['source_pl']: set(row['peer_ips']) for _, row in pl_by_source.iterrows()}
    
    pl_subnet_sets = {row['source_pl']: set(row['peer_subnets']) for _, row in pl_by_source.iterrows()}

    pl_asn_sets = {row['source_pl']: set(row['peer_asns']) for _, row in pl_by_source.iterrows()}

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

        as_intersection = len(pl_asn_sets[source1] & pl_asn_sets[source2])
        as_union = len(pl_asn_sets[source1] | pl_asn_sets[source2])
        as_jaccard = as_intersection / as_union if as_union > 0 else 0
    
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
            'as_jaccard': as_jaccard
        })
    
    overlap_df = pd.DataFrame(overlaps)

    return overlap_df

def peer_list_similarity(ban, threshold):

    ban = ban

    all_overlap_df = pd.DataFrame()

    for node in servers.keys():
        default_port = "18080"
        my_ip = servers[node]

        peers_df = pd.read_parquet(f"data/dataframes/peers_{node}_{ban}.parquet")

        overlap_df = analyze_local_pl_similarity(peers_df, my_ip)

        all_overlap_df = pd.concat([all_overlap_df, overlap_df], ignore_index=True)
    

    set_plt_latex_format()
    plt.figure(figsize=(3.13,1), dpi=300)
    plt.xlabel('Jaccard Similarity across IPs')
    plt.ylabel('Pair Count')
    plt.hist(all_overlap_df['ip_jaccard'], bins=100, range=(0,1), log=True, color='red')
    plt.savefig(f'results/graphs/{ban}_ip_similarity.pdf',
               bbox_inches='tight',
               pad_inches=0.1,
               dpi=300)
    plt.show()

    plt.figure(figsize=(3.13,1), dpi=300)
    plt.ylabel('Pair Count')
    plt.xlabel('Jaccard Similarity across Subnets')
    plt.hist(all_overlap_df['sub_jaccard'], bins=100, range=(0,1), log=True, color='red')
    plt.savefig(f'results/graphs/{ban}_sub_similarity.pdf',
               bbox_inches='tight',
               pad_inches=0.1,
               dpi=300)
    plt.show()

    plt.figure(figsize=(3.13,1), dpi=300)
    plt.ylabel('Pair Count')
    plt.xlabel('Jaccard Similarity across ASs')
    plt.hist(all_overlap_df['as_jaccard'], bins=100, range=(0,1), log=True, color='red')
    plt.savefig(f'results/graphs/{ban}_as_similarity.pdf',
               bbox_inches='tight',
               pad_inches=0.1,
               dpi=300)
    plt.show()

    high_overlap = all_overlap_df[all_overlap_df['sub_jaccard']>threshold]

    all_ips = pd.concat([high_overlap['source1_ip'], high_overlap['source2_ip']])

    ip_counts = all_ips.value_counts()

    frequent_ips = ip_counts[ip_counts > 1].index
    sus_ips = set(frequent_ips)

    # logging
    logging.info(f"PL Similarity - Unique IPs: {len(sus_ips)}")
    
    return sus_ips, overlap_df