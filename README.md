# monero-traffic-analysis

## Convenience Script
# Setup and Usage

## Prerequisites
- Python 3.x
- PCAP files for analysis: https://zenodo.org/records/16947083 (or your own capture)
- requirements.txt

## Installation Steps

1. **Load PCAP files**
   
   Either place all pcap file folders in the default directory structure:
   ```
   data/pcapng/<server_id>/*.pcapng
   ```
   or have a direct path ready as: 
   ```/path/to/your/nodes/data```
   , where the data folder should have similar structure as above, meaning:
   ```/path/to/your/nodes/data/<some_server_id>/*.pcapng```
   If working with the submission data which contians two separate configurations, the paths should look like:
   ```/path/to/submission/paper_w-banlist```
   ```/path/to/submission/paper_wo-banlist```

2. **Configure server mapping**
   
   Edit the `constants.py` file, adding your server_id as key and IP address as value:
   ```python
   servers = {
       "<some_server_id>": "<server_ip>"
   }
   ```
   The default configuration is set for the submission dataset. 

3. **Set up virtual environment**
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

4. **Download ASN database**
    To match IPs with ASN organizations download a respective database and save it as data/external/GeoLite2-ASN.mmdb.

    https://github.com/P3TERX/GeoLite.mmdb?tab=readme-ov-file

    (https://www.maxmind.com/en/geolite2/eula)

5. **Run the convenience script**
   
   With the virtual environment active, execute:
   ```bash
   ./convenience_script.sh
   ```
   If it is the first time running the script, choose "yes" when asked if the pcapng files should be processed.  
   Later, you can either click no to only run the analysis, start the analysis script main.py manually, or:
   If you prefer to go over the results step by step including checking the IP addresses, you can choose no when asked to proceed with the analysis and continue with step 6b.

6. **Analyze results**
   You should have various graphs as seen in the submission paper, as well as a complete list of IP addresses (results/identified_ns_ips.txt).
   
   b: Open and run `main_notebook.ipynb` to check the analysis results step by step.

# GeoLite2 Database
https://github.com/P3TERX/GeoLite.mmdb?tab=readme-ov-file
https://www.maxmind.com/en/geolite2/eula

# banlist
https://gist.github.com/Rucknium/76edd249c363b9ecf2517db4fab42e88
https://github.com/Boog900/monero-ban-list/blob/main/ban_list.txt 