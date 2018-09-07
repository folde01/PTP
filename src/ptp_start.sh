#!/usr/bin/env bash

if [ $# != 1 ] || ([ $1 != 'virtual' ] && [ $1 != 'physical' ]); then
    echo "Usage: $0 <virtual|physical>"
    exit 1
fi

TARGET_DEVICE_TYPE="$1"

#./ptp_networking.sh $TARGET_DEVICE_TYPE
#[ $? = 0 ] || ( 
    #echo "Networking setup failed. PTP not starting."
    #exit 1
#)

#./ptp_cipher_list.sh
#[ $? = 0 ] || ( 
#    echo "Warning: Could not download new cipher list."
#)

python ptp_init.py reinit
sudo rm -f sniffed.pcap
sudo PATH=$PATH python ptp_ui.py
