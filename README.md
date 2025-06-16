# monero-traffic-analysis

## Requirements
- Wireshark 4.4.6 
    - monero support added with 4.4.0, tested with 4.4.6
- Python3
    - tested with version 3.12.3
### Python Enviornment
- pandas 2.2.3

## File Capture
On the Monero host, we use dumpcap (included in a Wireshark installation) to capture and later work with the capture file efficiently. 
We assume a standard Monero setup behind port 18080.

```shell
dumpcap -i <interface> -f "port 18080" -b duration:<time_in_seconds> -b files:<n_files> -w <output_file>.pcapng
```
e.g. a capture for 1 day (rotates to create 12 files to avoid overly large files):
``dumpcap -i eth0 -f "port 18080" -a duration:86400 -b duration:7200 -b files:12 -w capture.pcapng``

## Convenience Script
Using the convenience script 

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

## ToDo
- [ ] visualize command sequence patterns
- [ ] monero signautre only statistics
- [ ] last_seen and support flags statistics
- [ ] 

## Goal Metrics
### Peer Lists
- [o] Similarity of individual peer lists 
- [x] Similarity of total unique peers sent
- [o] Peer popularity based on peer list appearance 
- [o] (Network Analysis based on Popularity Topology?)
- [ ] 
### Packet Fragmentation
- [o] Monero signature only in a single TCP packet
- [ ] 
### Command Sequence
- [x] measure timed_sync latency
- [x] measure Pings
- [ ] 
### Packet Structure
- [o] last_seen timestamp
- [o] support_flag not set
- [ ] 

# GeoLite2 Database
https://github.com/P3TERX/GeoLite.mmdb?tab=readme-ov-file
https://www.maxmind.com/en/geolite2/eula

# banlist
https://gist.github.com/Rucknium/76edd249c363b9ecf2517db4fab42e88
https://github.com/Boog900/monero-ban-list/blob/main/ban_list.txt
