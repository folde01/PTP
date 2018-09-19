#!/usr/bin/env bash

function get_new_cipher_list()
{ 
    echo "Configuring cipher list."
    ./ptp_cipher_list.sh > /dev/null 2>&1
    [ $? = 0 ] || ( 
        echo "Warning: Could not download new cipher list."
    )
}


# main

get_new_cipher_list
python ptp_init.py reinit
sudo rm -f sniffed.pcap
sudo PATH=$PATH python ptp_controller.py
