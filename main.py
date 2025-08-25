from constants import servers
import anomaly_functions

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



def main(ban):
    anomaly_dict = {}

    # Basic Summary Stats + Syntactic Violations: Support Flags Omission and Last Seen Transmission
    support_flags_sources, lastseen_sources, basic_stats = anomaly_functions.stats_syntactic(ban)
    anomaly_dict['SF Omission'] = {}
    anomaly_dict['SF Omission']['ips'] = list(support_flags_sources)
    anomaly_dict['SF Omission']['asns'] = list({ip_to_asn(ip) for ip in anomaly_dict['SF Omission']['ips']})
    anomaly_dict['LS Transmission'] = {}
    anomaly_dict['LS Transmission']['ips'] = list(lastseen_sources)
    anomaly_dict['LS Transmission']['asns'] = list({ip_to_asn(ip) for ip in anomaly_dict['LS Transmission']['ips']})

    # Peer List Diversity
    pl_div_ips, max_announced_subnets, median_announced_subnets = anomaly_functions.peer_list_diversity(ban, threshold=0.1)
    anomaly_dict['PL Diversity'] = {}
    anomaly_dict['PL Diversity']['ips'] = list(pl_div_ips)
    anomaly_dict['PL Diversity']['asns'] = list({ip_to_asn(ip) for ip in anomaly_dict['PL Diversity']['ips']})

    # Peer List Similarity
    pl_sim_ips, overlap_df = anomaly_functions.peer_list_similarity(ban, threshold=0.3)
    anomaly_dict['PL Similarity'] = {}
    anomaly_dict['PL Similarity']['ips'] = list(pl_sim_ips)
    anomaly_dict['PL Similarity']['asns'] = list({ip_to_asn(ip) for ip in anomaly_dict['PL Similarity']['ips']})

    # ID:IP Anomalies
    sus_id_cluster_ips, sus_id_anomaly_ips, interection_ips, union_ips, id_count_dist, num_clusters = anomaly_functions.node_ids(ban=ban)
    anomaly_dict['ID:IP Anomaly'] = {}
    #anomaly_dict['ID:IP Anomaly']['ips'] = list(sus_id_anomaly_ips)
    #anomaly_dict['ID:IP Anomaly']['ips'] = list(sus_id_cluster_ips)
    anomaly_dict['ID:IP Anomaly']['ips'] = list(union_ips)
    anomaly_dict['ID:IP Anomaly']['asns'] = list({ip_to_asn(ip) for ip in anomaly_dict['ID:IP Anomaly']['ips']})

    # Connection Anomalies
    sus_short, sus_ping, sus_ts, all_latencies, conn_df = anomaly_functions.connections(ban=ban, threshold=90, min_tss=10) 
    anomaly_dict['Short-lived Conn'] = {}
    anomaly_dict['Ping Flooding'] = {}
    anomaly_dict['Throttled TS'] = {}
    anomaly_dict['Short-lived Conn']['ips'] = list(sus_short)
    anomaly_dict['Short-lived Conn']['asns'] = list({ip_to_asn(ip) for ip in anomaly_dict['Short-lived Conn']['ips']})
    anomaly_dict['Ping Flooding']['ips'] = list(sus_ping)
    anomaly_dict['Ping Flooding']['asns'] = list({ip_to_asn(ip) for ip in anomaly_dict['Ping Flooding']['ips']})
    anomaly_dict['Throttled TS']['ips'] = list(sus_ts)
    anomaly_dict['Throttled TS']['asns'] = list({ip_to_asn(ip) for ip in anomaly_dict['Throttled TS']['ips']})

    # Signature-only IPs (and ban listed)
    banned_ips, signature_only_ips = anomaly_functions.ban_and_signature(ban=ban)
    anomaly_dict['Signature Only'] = {}
    anomaly_dict['Signature Only']['ips'] = list(signature_only_ips)
    anomaly_dict['Signature Only']['asns'] = list({ip_to_asn(ip) for ip in anomaly_dict['Signature Only']['ips']})
    anomaly_dict['Ban Listed'] = {}
    anomaly_dict['Ban Listed']['ips'] = list(banned_ips)
    anomaly_dict['Ban Listed']['asns'] = list({ip_to_asn(ip) for ip in anomaly_dict['Ban Listed']['ips']})

    # Subnet and ASN Saturation
    sus_subnet_ips, lion_peers, median_subnet_peers = anomaly_functions.subnets_asn_comb(ban=ban)
    #anomaly_dict['High Subnet Sat'] = {}
    #anomaly_dict['High Subnet Sat']['ips'] = list(sus_subnet_ips)
    #anomaly_dict['High Subnet Sat']['asns'] = list({ip_to_asn(ip) for ip in anomaly_dict['High Subnet Sat']['ips']})

    # In-Degree analysis
    indegrees = pd.DataFrame(anomaly_functions.indegree(ban))

    # Final Eval
    identified_ns_peers = anomaly_functions.summarize_IPs_plot_overlap(ban, anomaly_dict)
    
    all_ns_peers = anomaly_functions.save_ns_peers(identified_ns_peers)

    saturation_stats = anomaly_functions.plot_anom_saturation(ban, total_anomaly_set=identified_ns_peers)

    reachable_peers = anomaly_functions.reachable(ban, identified_ns_peers)

    ban_list_stats = anomaly_functions.compare_to_banlist(identified_ns_peers)

    pl_poison = anomaly_functions.pl_poison_dist(ban, identified_ns_peers)

    network_distribution = anomaly_functions.network_distribution(ban, identified_ns_peers)

    anomaly_functions.format_and_write_tex(ban, basic_stats, anomaly_dict, conn_df, all_latencies, indegrees, 
                         sus_id_anomaly_ips, sus_id_cluster_ips, num_clusters, median_subnet_peers, 
                         identified_ns_peers, reachable_peers, lion_peers, saturation_stats, 
                         ban_list_stats, pl_poison)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 main.py with")
        sys.exit(1)
    
    ban = sys.argv[1]

    main(ban)

    