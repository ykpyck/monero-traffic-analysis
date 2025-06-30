#!/bin/bash

if [[ -f .env ]]; then
    set -a  # automatically export all variables
    source .env
    set +a  # turn off automatic export
fi

read -p "Process .pcapng files? (y/n): " process_pcapng

if [[ $process_pcapng =~ ^[Yy]$ ]]; then
    # Check if data/pcapng directory exists
    # /media/kopy/Transcend/monero_pcap/paper_w-banlist
    # if [ ! -d "data/pcapng" ]; then
    if [ ! -d "/media/kopy/Transcend/monero_pcap/paper_wo-banlist" ]; then
        echo "Directory data/pcapng does not exist"
        exit 1
    fi
    
    # Loop through each subdirectory in data/pcapng
    #for subdir in data/pcapng/*/; do
    for subdir in /media/kopy/Transcend/monero_pcap/paper_wo-banlist/*/; do
        # Check if subdirectories exist
        if [ ! -d "$subdir" ]; then
            echo "No subdirectories found in data/pcapng/"
            exit 1
        fi
        
        # Extract subdirectory name
        subdir_name=$(basename "$subdir")

        #if [ "$subdir_name" = "archive" ]; then
        if [[ "$subdir_name" =~ ^(syd|archive|sgp|sfo|blr)$ ]]; then
            echo "Skipping archive directory: $subdir_name"
            continue
        fi

        echo "Found subdirectory: $subdir_name"
        
        var_name="$subdir_name"

        ip_value="${!var_name}"

        if [[ -n "$ip_value" ]]; then
            echo "Using IP from .env file for $subdir_name: $ip_value"
            name="$ip_value"
        else
            echo "No IP found in .env file for $subdir_name"
            # Ask for IP for this specific subdirectory
            read -p "Enter the Monero host IP for $subdir_name: " name
        fi

        echo "Selected IP: $name"
        
        # Process each .pcapng file in this subdirectory
        pcapng_found=false
        for pcapng_file in "$subdir"*.pcapng; do
            # Check if files exist (handles case where no .pcapng files are found)
            if [ ! -f "$pcapng_file" ]; then
                continue
            fi
            
            pcapng_found=true
            
            # Extract filename without path and extension
            capture_file=$(basename "$pcapng_file" .pcapng)
            echo "Processing: $subdir_name/$capture_file.pcapng"
            
            # Create output directory structure if it doesn't exist
            mkdir -p "data/tsv/$subdir_name"

            mkdir -p "results"

            #tshark -r "$pcapng_file" \
            # -Y "tcp.len == 8 && tcp.payload contains 01:21:01:01:01:01:01:01" \
            # -T fields \
            # -e ip.src \
            #| sort -u >> data/results/signature_only_ips.csv
            
            # Execute tshark command
            #                -Y "(monero) && (ip.dst==$name)" \
            tshark -r "$pcapng_file" \
                -Y "(monero)" \
                -T fields \
                -e frame.time_epoch -e ip.src -e ip.dst \
                -e monero.command -e monero.flags \
                -e tcp.segment.count -e tcp.len -e tcp.srcport -e tcp.dstport \
                -e monero.payload.item.key -e monero.payload.item.type \
                -e monero.payload.item.value.uint64 -e monero.payload.item.value.uint32 \
                -e monero.payload.item.value.uint16 \
                -e monero.payload.item.value.uint8 -e monero.payload.item.value.string \
                > "data/tsv/$subdir_name/${capture_file}_packets.tsv"
            
            # Check if the command was successful
            if [ $? -eq 0 ]; then
                echo "Successfully processed: $subdir_name/$capture_file.pcapng -> $subdir_name/${capture_file}_packets.tsv"
            else
                echo "Error processing: $subdir_name/$capture_file.pcapng"
            fi
        done
        
        if [ "$pcapng_found" = false ]; then
            echo "No .pcapng files found in $subdir_name/"
        fi
        
        echo "Finished processing subdirectory: $subdir_name"
        echo "---"
    done
else
    echo "Skipping pcapng processing."
fi

echo "Processing pcapng files complete."

if [ ! -d "data/tsv" ]; then
    echo "Directory data/tsv does not exist"
    exit 1
fi

# Process TSV files in subdirectories
tsv_found=false
for subdir in data/tsv/*/; do
    # Check if subdirectories exist
    if [ ! -d "$subdir" ]; then
        continue
    fi
    
    # Extract subdirectory name
    subdir_name=$(basename "$subdir")
    echo "Processing subdirectory: $subdir_name"
    
    # Process each .tsv file in this subdirectory
    subdir_tsv_found=false
    for tsv_file in "$subdir"*.tsv; do
        if [ ! -f "$tsv_file" ]; then
            continue
        fi
        
        tsv_found=true
        subdir_tsv_found=true
        
        # Extract filename without path and extension
        tsv_basename=$(basename "$tsv_file" .tsv)
        echo "Processing: $subdir_name/$tsv_basename.tsv"
        
        mkdir -p "data/packets/$subdir_name"

        # Call Python script with full path
        python3 extract_packet_data_to_json.py "$tsv_file" "data/packets/$subdir_name/${tsv_basename}.json"
        
        if [ $? -eq 0 ]; then
            echo "Successfully processed: $subdir_name/$tsv_basename.tsv -> $subdir_name/$tsv_basename.json"
        else
            echo "Error processing: $subdir_name/$tsv_basename.tsv"
        fi
    done
    
    if [ "$subdir_tsv_found" = false ]; then
        echo "No .tsv files found in $subdir_name/"
    fi
    
    echo "Finished processing subdirectory: $subdir_name"
    echo "---"
done

# Initiate final analysis script 
echo "Final analysis initiated..."
#python analysis.py