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
e.g. a capture for 1 day (rotates to create 10 files to avoid overly large files):
``dumpcap -i eth0 -f "port 18080" -b duration:86400 -b files:10 -w monero_capture.pcapng``

## File Preprocessing
If not directly saved, load all capture files directly to the repo's pcapng folder.
Continue with either running the convenience script (will process all pcapng files in the pcapng folder) or execute the individual commands for a specific capture file.

### Individual Commands 

#### Peerlist Extraction
First, tshark filters all Timed Sync commands and retrieves all necessary data.
```shell
tshark -r data/pcapng/<capture_file>.pcapng \
 -Y "((monero.command == 1001 || monero.command == 1002) && (ip.dst == 192.168.2.128)) && (monero.return_code == 1)" \
 -T fields \
 -e frame.time_epoch -e ip.src -e monero.command \
 -e monero.payload.item.key -e monero.payload.item.type \
 -e monero.payload.item.value.uint32 -e monero.payload.item.value.uint16 \
 -e monero.payload.item.value.uint8 -e monero.payload.item.value.uint64 \
> data/tsv/<capture_file>_peerlists.tsv 
```
Second, a Python script will extract relevant peer list information and brings it into an accessabile format for later analysis. 
```shell
python3 extract_peerlists_to_json.py data/tsv/<capture_file>_peerlists.tsv
```

# Current Testing Command
```shell
tshark -r data/pcapng/chunk_2h__00000_20250516142013.pcapng \
 -Y "(monero) && (ip.dst==192.168.2.128)" \
 -T fields \
 -e frame.time_epoch -e ip.src -e monero.command \
 -e monero.payload.item.key -e monero.payload.item.type \
 -e monero.payload.item.value.uint64 -e monero.payload.item.value.uint32 \
 -e monero.payload.item.value.uint16 \
 -e monero.payload.item.value.uint8 -e monero.payload.item.value.string \
> data/tsv/chunk_2h__00000_20250516142013_minfilter.tsv
```
5 monero.payload.item.value.uint64
6 monero.payload.item.value.uint32
7 monero.payload.item.value.uint16
8 monero.payload.item.value.uint8
10 monero.payload.item.value.string
11 boolean type but value is sent as monero.payload.item.value.uint64
12 monero.payload.item.value.struct -> not extracted (whole struct would be redundant)
138 array struing
140 array struct -> not extracted (whole struct would be redundant)

#### Monero Extraction
```shell
tshark -r data/pcapng/<capture_file>.pcapng \
 -Y "((monero) && (ip.dst == <monero_host_IP>))" \
 -T fields \
 -e frame.time_epoch -e ip.src -e monero.command \
 -e tcp.segment.count -e tcp.len \
> data/tsv/<capture_file>.tsv
```

#### Monero Signature Only Extraction
```shell
tshark -r data/pcapng/chunk_2h__00000_20250516142013.pcapng \
 -Y "tcp.len == 8 && tcp.payload contains 01:21:01:01:01:01:01:01" \
 -T fields \
 -e frame.time_epoch -e ip.src -e ip.dst \
 -e tcp.len -e tcp.payload \
> data/tsv/chunk_2h__00000_20250516142013_tcp.tsv
```

## ToDo
extended the python extraction script to retrieve data along Current Testing Command
-> this command will most certainly act as the main command to retrieve monero data, following is to be added 
- [ ] packet data including, 
- [ ] req/resp flag
- [ ] payload length
- [ ] number of tcp segments
- [ ]

## Goal Metrics
### Peer Lists
- [ ] Similarity of individual peer lists 
- [ ] Similarity of total unique peers sent
- [ ] Peer popularity based on peer list appearance 
- [ ] (Network Analysis based on Popularity Topology?)
- [ ] 
### Packet Fragmentation
- [ ] Monero signature only in a single TCP packet
- [ ] Fragmentation higher than necessary for total bytes sent
- [ ] 
### Packet Structure
- [ ] last_seen timestamp
- [ ] support_flag not set
- [ ] 
- [ ]
- [ ]


# Digital Ocean Droplet Setup
apt update
apt upgrade -y
ufw allow 18080
apt install bzip2 -y
reboot

wget https://downloads.getmonero.org/linux64
mkdir monero
tar -xjvf linux64 -C monero
cd monero/monero-x86_64-linux-gnu-v0.18.4.0/
./monerod --prune-blockchain --detach
./monerod status