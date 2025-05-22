# monero-traffic-analysis

## Requirements
Wireshark 4.4.6 
- monero support added with 4.4.0, tested with 4.4.6
- Python3

## File Capture
- on Monero host (dumpcap or tshark installed)
- assumes standard Monero setup behind port 18080
``dumpcap -i <interface> -f "port 18080" -b duration:<time_in_seconds> -b files:<n_files> -w <output_file>.pcapng``
e.g. a capture for 7 days with each day having its own pcap file:
``dumpcap -i eth0 -f "port 18080" -b duration:86400 -b files:7 -w monero_capture.pcapng``

## File Preprocessing
- save or load the capture directly to the repo's inputs folder

```shell
tshark -r data/inputs/16052025_1_hour_eth0.pcapng \  
    -Y "((monero.command == 1002) && (ip.dst == 192.168.2.128)) && (monero.return_code == 1)" \
    -T fields \
    -e frame.time_epoch -e ip.src \
    -e monero.payload.item.key -e monero.payload.item.type \
    -e monero.payload.item.value.uint32 -e monero.payload.item.value.uint16 \
    -e monero.payload.item.value.uint8 -e monero.payload.item.value.uint64 \
    > data/tsv/16052025_1_hour_eth0.tsv 
```

```shell
python3 extract_monero_peers.py data/tsv/16052025_1_hour_eth0.tsv
```