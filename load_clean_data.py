import json
import pandas as pd
from pathlib import Path
from constants import servers
import os

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

def de_duplicate(peer_packets_df):
    has_comma_cmd = peer_packets_df['command'].str.contains(',', na=False)
    has_comma_flags = peer_packets_df['monero_flags'].str.contains(',', na=False)
    has_comma = has_comma_cmd | has_comma_flags

    explode_rows = peer_packets_df[has_comma].copy()
    keep_rows = peer_packets_df[~has_comma].copy()

    new_rows = []

    for idx, row in explode_rows.iterrows():
        # split values
        command_list = str(row['command']).split(',')
        flags_list = str(row['monero_flags']).split(',')

        # pair new values
        for cmd, flag in zip(command_list, flags_list):
            new_row = row.copy()
            new_row['command'] = cmd.strip()
            new_row['monero_flags'] = flag.strip()
            new_rows.append(new_row)

    # Create DataFrame from exploded rows
    exploded_df = pd.DataFrame(new_rows)

    # Combine with rows that didn't need exploding
    peer_packets_df = pd.concat([keep_rows, exploded_df], ignore_index=True).sort_values(['timestamp'])

    return peer_packets_df


def main():
    # in complete script do: for node in servers.keys()

    node = 'sfo'
    for node in servers.keys():
        folder_path=Path(f"data/packets/{node}")

        if not folder_path.exists():
            continue

        my_ip = servers[node]

        peer_packets_df, peers_df = load_json(folder_path=folder_path)
        # some data cleaning
        peer_packets_df = de_duplicate(peer_packets_df)

        command_list = [
            '1001',     # Handshake
            '1002',     # Timed Sync    
            '1003',     # Ping
            '1007',     # Req. Support Flags
            '2001',     # 
            '2002',     # New Transaction
            '2003',
            '2004',
            '2006',
            '2007',
            '2008',
            '2009',
            '2010'
        ]

        peer_packets_df = peer_packets_df[peer_packets_df['command'].isin(command_list)]
        peer_packets_df['timestamp'] = pd.to_datetime(peer_packets_df['timestamp'])

        peer_packets_df.to_parquet(f"data/dataframes/peer_packets_{node}.parquet", index=False)
        peers_df.to_parquet(f"data/dataframes/peers_{node}.parquet", index=False)


if __name__ == '__main__':
    main()

