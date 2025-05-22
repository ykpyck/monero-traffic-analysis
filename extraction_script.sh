#!/bin/bash

read -p "Enter the Monero host IP: " name

# Process each .pcapng file in the data/pcapng directory
for pcapng_file in data/pcapng/*.pcapng; do
    # Check if files exist (handles case where no .pcapng files are found)
    if [ ! -f "$pcapng_file" ]; then
        echo "No .pcapng files found in data/pcapng/"
        exit 1
    fi
    
    # Extract filename without path and extension
    capture_file=$(basename "$pcapng_file" .pcapng)
    
    echo "Processing: $capture_file.pcapng"
    
    # Execute tshark command
    tshark -r "$pcapng_file" \
        -Y "((monero.command == 1002) && (ip.dst == $name)) && (monero.return_code == 1)" \
        -T fields \
        -e frame.time_epoch -e ip.src \
        -e monero.payload.item.key -e monero.payload.item.type \
        -e monero.payload.item.value.uint32 -e monero.payload.item.value.uint16 \
        -e monero.payload.item.value.uint8 -e monero.payload.item.value.uint64 \
        > "data/tsv/${capture_file}.tsv"
    
    # Check if the command was successful
    if [ $? -eq 0 ]; then
        echo "Successfully processed: $capture_file.pcapng -> $capture_file.tsv"
    else
        echo "Error processing: $capture_file.pcapng"
    fi
done

echo "Processing pcapng files complete."

for tsv_file in data/tsv/*tsv; do 
    if [ ! -f "$tsv_file" ]; then
        echo "No .tsv files found in data/tsv/"
        exit 1
    fi

    tsv_file=$(basename "$tsv_file" .tsv)

    echo "Processing: $tsv_file.pcapng"

    python3 extract_peerlists_to_json.py data/tsv/$tsv_file.tsv

    if [ $? -eq 0 ]; then
        echo "Successfully processed: $tsv_file.tsv -> $tsv_file.json"
    else
        echo "Error processing: $tsv_file.tsv"
    fi
done

echo "Successfully extracted all peer lists!"