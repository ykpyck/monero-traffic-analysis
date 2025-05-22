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
e.g. a capture for 1 day (rotates to create 4 files to avoid overly large files):
``dumpcap -i eth0 -f "port 18080" -b duration:86400 -b files:4 -w monero_capture.pcapng``

## File Preprocessing
If not directly saved, load all capture files directly to the repo's pcapng folder.
Continue with either running the convenience script (will process all pcapng files in the pcapng folder) or execute the individual commands for a specific capture file.

### Individual Commands 

#### Peerlist Extraction
First, tshark will filter all Timed Sync commands and retrieves all necessary data.
```shell
tshark -r data/pcapng/<capture_file>.pcapng \  
  -Y "((monero.command == 1002) && (ip.dst == 192.168.2.128)) && (monero.return_code == 1)" \
  -T fields \
  -e frame.time_epoch -e ip.src \
  -e monero.payload.item.key -e monero.payload.item.type \
  -e monero.payload.item.value.uint32 -e monero.payload.item.value.uint16 \
  -e monero.payload.item.value.uint8 -e monero.payload.item.value.uint64 \
  > data/tsv/<capture_file>.tsv 
```
Second, a Python script will extract relevant peer list information and brings it into an accessabile format for later analysis. 
```shell
python3 extract_peerlists_to_json.py data/tsv/<capture_file>.tsv
```

tshark -r data/pcapng/capture_20250121_172717.pcapng -Y "((monero.command == 1002) && (ip.dst == 10.200.1.2)) && (monero.return_code == 1)" -T fields -e frame.time_epoch -e ip.src -e monero.payload.item.key -e monero.payload.item.type -e monero.payload.item.value.uint32 -e monero.payload.item.value.uint16 -e monero.payload.item.value.uint8 -e monero.payload.item.value.uint64 > capture_20250121_172717.tsv