#!/bin/bash

eval $(python3 -c "
import sys
sys.path.append('.')
from constants import servers
for key, value in servers.items():
    print(f'{key}={value}')
")

read -p "Process .pcapng files? (y/n): " process_pcapng

pcapng_dir=${pcapng_dir:-"data/pcapng"}

read -p 'Enter a capture identifier, like "with" or "without" ban list to identify the results if run multiple times with different data sets: ' identifier
if [[ $process_pcapng =~ ^[Yy]$ ]]; then

    read -p "Enter the path to your pcapng directory [default: data/pcapng]: " pcapng_dir

    pcapng_dir=${pcapng_dir:-"data/pcapng"}

    # Check if data/pcapng directory exists
    if [ ! -d "$pcapng_dir" ]; then
        echo "Directory '$pcapng_dir' does not exist"
        exit 1
    fi
    
    # Loop through each subdirectory in data/pcapng
    for subdir in "$pcapng_dir"/*/; do
        # Check if subdirectories exist
        if [ ! -d "$subdir" ]; then
            echo "No subdirectories found in '$pcapng_dir/'"
            exit 1
        fi
        
        # Extract subdirectory name
        subdir_name=$(basename "$subdir")

        #if [ "$subdir_name" = "archive" ]; then
        if [[ "$subdir_name" =~ ^(archive)$ ]]; then #(syd|archive|sgp|ams|blr)$ ]]; then
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

            tshark -r "$pcapng_file" \
             -Y "tcp.len == 8 && tcp.payload contains 01:21:01:01:01:01:01:01" \
             -T fields \
             -e ip.src \
            | sort -u >> results/signature_only_ips.csv
            
            # process pcaps letting the monero dissector decide
            tshark -r "$pcapng_file" \
                -o "monero.desegment:True" \
                -Y "(monero)" \
                -T fields \
                -e frame.number -e frame.time_epoch -e ip.src -e ip.dst \
                -e monero.command -e monero.flags \
                -e tcp.segment.count -e tcp.len -e tcp.srcport -e tcp.dstport \
                -e monero.payload.item.key -e monero.payload.item.type \
                -e monero.payload.item.value.uint64 -e monero.payload.item.value.uint32 \
                -e monero.payload.item.value.uint16 \
                -e monero.payload.item.value.uint8 -e monero.payload.item.value.string \
                > "data/tsv/$subdir_name/${capture_file}_packets_reassembled.tsv"
            
            # process again by force every packet without reassemly 
            tshark -r "$pcapng_file" \
                -o "monero.desegment:False" \
                -Y "(monero)" \
                -T fields \
                -e frame.number -e frame.time_epoch -e ip.src -e ip.dst \
                -e monero.command -e monero.flags \
                -e tcp.segment.count -e tcp.len -e tcp.srcport -e tcp.dstport \
                -e monero.payload.item.key -e monero.payload.item.type \
                -e monero.payload.item.value.uint64 -e monero.payload.item.value.uint32 \
                -e monero.payload.item.value.uint16 \
                -e monero.payload.item.value.uint8 -e monero.payload.item.value.string \
                -e _ws.unreassembled \
                > "data/tsv/$subdir_name/${capture_file}_packets_not.tsv"
            
            # remove all packets that could have been reassembled (already present in first tsv)
            awk -F'\t' 'NF < 18 || $18 == "" {for(i=1;i<=17;i++) printf "%s%s", $i, (i==17?"\n":"\t")}' \
                "data/tsv/$subdir_name/${capture_file}_packets_not.tsv" > \
                "data/tsv/$subdir_name/${capture_file}_packets_not_filtered.tsv"
            
            mv "data/tsv/$subdir_name/${capture_file}_packets_not_filtered.tsv" \
               "data/tsv/$subdir_name/${capture_file}_packets_not.tsv"
            
            # combine both tsvs and remove duplicats -> duplicates occur when it is a by default not reassembled packet (small not fragmented)
            {
                cat "data/tsv/$subdir_name/${capture_file}_packets_reassembled.tsv"
                cat "data/tsv/$subdir_name/${capture_file}_packets_not.tsv"
            } | sort -t$'\t' -k1,1n -u > "data/tsv/$subdir_name/${capture_file}_packets.tsv"
            
            rm data/tsv/$subdir_name/${capture_file}_packets_not.tsv
            rm data/tsv/$subdir_name/${capture_file}_packets_reassembled.tsv
            
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

    rm -r data/tsv/$subdir_name/
    echo "Finished processing subdirectory: $subdir_name"
    echo "---"
done

# Initiate loading and cleaning script 
echo "load and clean the data..."

if [[ $process_pcapng =~ ^[Yy]$ ]]; then
    python3 load_clean_data.py $identifier
fi

echo "Datasets ready."

echo "Continue with anomaly analysis? (y/n)"
echo "Will auto-continue with 'y' in 3 minutes if no input..."

read -t 180 -p "Your choice: " analysis
if [[ $? -eq 142 ]]; then
    echo -e "\nTimeout reached. Automatically continuing with analysis..."
    analysis="y"
fi

if [[ $analysis =~ ^[Yy]$ ]]; then
    python3 main.py $identifier
fi