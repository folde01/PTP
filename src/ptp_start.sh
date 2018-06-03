#!/usr/bin/env bash

python ptp_init.py reinit
rm -f sniffed.pcap
sudo PATH=$PATH python ptp_ui.py
