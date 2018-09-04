#!/usr/bin/env bash

#sudo iptables -t nat -A POSTROUTING -o enp0s3 -j MASQUERADE && iptables-save
#sudo service pptpd restart

python ptp_init.py reinit
sudo rm -f sniffed.pcap
sudo PATH=$PATH python ptp_ui.py
