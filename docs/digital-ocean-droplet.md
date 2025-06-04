# Digital Ocean Droplet Setup

## Basic Setup
```shell
apt update
apt upgrade -y
ufw allow 18080
apt install bzip2 -y
wget https://downloads.getmonero.org/linux64
mkdir monero
tar -xjvf linux64 -C monero
```

## System Service 
(for automated start after boot)
```shell
nano /etc/systemd/system/monerod.service
# add below config
systemctl daemon-reload
systemctl enable monerod.service
reboot
```
Add: 
```shell
[Unit]
Description=Monero Daemon
After=network.target

[Service]
Type=forking
User=root
WorkingDirectory=/root/monero/monero-x86_64-linux-gnu-v0.18.4.0/
ExecStart=/root/monero/monero-x86_64-linux-gnu-v0.18.4.0/monerod --prune-blockchain --ban-list /root/.bitmonero/ban.txt --detach
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```