# monero-traffic-analysis

## Convenience Script
# Setup and Usage

## Prerequisites
- Python 3.x
- PCAP files for analysis

## Installation Steps

1. **Load PCAP files**
   
   Place all pcap files in the following directory structure:
   ```
   data/pcapng/<server_id>/
   ```

2. **Configure server mapping**
   
   Edit the `constants.py` file, adding your server_id as key and IP address as value:
   ```python
   servers = {
       "<server_id>": "<server_ip>"
   }
   ```

3. **Set up virtual environment**
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

4. **Run extraction script**
   
   With the virtual environment active, execute:
   ```bash
   ./extraction_script.sh
   ```

5. **Download ASN database**
    To match IPs with ASN organizations download a respective database and save it as data/external/GeoLite2-ASN.mmdb.
    https://github.com/P3TERX/GeoLite.mmdb?tab=readme-ov-file
    https://www.maxmind.com/en/geolite2/eula

6. **Analyze results**
   
   Open and run `final_notebook.ipynb` to check the analysis results.




## Details:


## File Capture
On the Monero host, we use dumpcap (included in a Wireshark installation) to capture and later work with the capture file efficiently. 
We assume a standard Monero setup behind port 18080.

```shell
dumpcap -i <interface> -f "port 18080" -b duration:<time_in_seconds> -b files:<n_files> -w <output_file>.pcapng
```
e.g. a capture for 1 day (rotates to create 12 files to avoid overly large files):
``dumpcap -i eth0 -f "port 18080" -a duration:86400 -b duration:7200 -b files:12 -w capture.pcapng``
   

## File Preprocessing
If not directly saved, load all capture files directly to the repo's pcapng folder.
Continue with either running the convenience script (will process all pcapng files in the pcapng folder) or execute the individual commands for a specific capture file.

### Individual Commands 

#### Monero Packet Extraction
First, tshark filters all Timed Sync commands and retrieves all necessary data.
```shell
 tshark -r data/pcapng/<capture_file>.pcapng \
 -Y "(monero) && (ip.dst==<host_ip>)" \
 -T fields \
 -e frame.time_epoch -e ip.src \
 -e monero.command -e monero.flags \
 -e tcp.segment.count -e tcp.len -e tcp.srcport \
 -e monero.payload.item.key -e monero.payload.item.type \
 -e monero.payload.item.value.uint64 -e monero.payload.item.value.uint32 \
 -e monero.payload.item.value.uint16 \
 -e monero.payload.item.value.uint8 -e monero.payload.item.value.string \
> data/tsv/<capture_file>_packets.tsv
```
Second, a Python script will extract relevant peer list information and brings it into an accessabile format for later analysis. 
```shell
python3 extract_packet_data_to_json.py data/tsv/<capture_file>_packets.tsv
```

# Current Testing Command
```shell
tshark -r data/pcapng/ams/20250603-ams_24_hour_capture_00004_20250603143550.pcapng \
 -Y "tcp.len == 8 && tcp.payload contains 01:21:01:01:01:01:01:01" \
 -T fields \
 -e ip.src \
> data/tsv/signature_only_ips.tsv
```

#### Monero Signature Only Extraction
```shell
tshark -r data/pcapng/<capture_file>.pcapng \
 -Y "tcp.len == 8 && tcp.payload contains 01:21:01:01:01:01:01:01" \
 -T fields \
 -e ip.src \
| sort -u >> data/results/signature_only_ips.csv
```

tshark -r "/media/kopy/Transcend/monero_pcap/paper_wo-banlist/ams/20250602-ams_24_hour_capture_00006_20250602164641.pcapng" \
 -Y "tcp.len == 8 && tcp.payload contains 01:21:01:01:01:01:01:01" \
 -T fields -e ip.src | sort -u >> results/signature_only_ips.csv

## ToDo
- [ ] visualize command sequence patterns
- [ ] monero signautre only statistics
- [ ] last_seen and support flags statistics
- [ ] 

## Goal Metrics
### Peer Lists
- [] Similarity of all individual peer lists
- [] Similarity of all individual peer lists excluding self comparison
- [] Similarity of total unique peers sent
- [] Peer list stats: number of peer lists, peers, unique peers
- [] Peer popularity based on peer list appearance 
- [] (Network Analysis based on Popularity Topology?)
- [] 
### Packet Fragmentation
- [] Monero signature only in a single TCP packet
- [] 
### Command Sequence
- [] timed sync frequency per connection
- [] pings per connection
- [] 
### Evident Deviations
- [result_df['has_support_flags']] last_seen timestamp
- [] support_flag not set
- [] 
### Node Attributes
- [result_df['unique_my_ports']] my_ports
- [result_df['unique_peer_ids']] unique_peer_ids
- [result_df[f'peer_id_cluster_{node}']] peer_id_cluster (shared peer IDs among distinct IPs)
- [result_df['unique_rpc_ports']] unique_rpc_ports

# GeoLite2 Database
https://github.com/P3TERX/GeoLite.mmdb?tab=readme-ov-file
https://www.maxmind.com/en/geolite2/eula

# banlist
https://gist.github.com/Rucknium/76edd249c363b9ecf2517db4fab42e88
https://github.com/Boog900/monero-ban-list/blob/main/ban_list.txt
