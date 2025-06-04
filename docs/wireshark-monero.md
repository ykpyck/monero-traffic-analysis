# Wireshark Monero Cheatsheet

## Types
5 monero.payload.item.value.uint64
6 monero.payload.item.value.uint32
7 monero.payload.item.value.uint16
8 monero.payload.item.value.uint8
10 monero.payload.item.value.string
11 boolean type but value is sent as monero.payload.item.value.uint64
12 monero.payload.item.value.struct -> not extracted (whole struct would be redundant)
138 array string
140 array struct -> not extracted (whole struct would be redundant)






## Archive
```shell
tshark -r data/pcapng/<capture_file>.pcapng \
 -Y "((monero.command == 1001 || monero.command == 1002) && (ip.dst == 192.168.2.128)) && (monero.return_code == 1)" \
 -T fields \
 -e frame.time_epoch -e ip.src -e monero.command \
 -e monero.payload.item.key -e monero.payload.item.type \
 -e monero.payload.item.value.uint32 -e monero.payload.item.value.uint16 \
 -e monero.payload.item.value.uint8 -e monero.payload.item.value.uint64 \
> data/tsv/<capture_file>_peerlists.tsv

rsync -avz --progress user@your-droplet-ip:/path/to/source/ /local/destination/
```