#!/usr/bin/env bash

if [ $# != 1 ] || ([ $1 != 'virtual' ] && [ $1 != 'physical' ] && [ $1 != 'last' ]); then
    echo "Usage: $0 <virtual|physical|last>"
    exit 1
fi

TARGET_DEVICE_TYPE="$1"

function configure_network() 
{ 
    echo "Configuring network."
    ./ptp_networking.sh $TARGET_DEVICE_TYPE
    [ $? = 0 ] || ( 
        echo "Networking setup failed. PTP not starting."
        exit 1
    )

    sleep 5
}

function get_new_cipher_list()
{ 
    echo "Configuring cipher list."
    ./ptp_cipher_list.sh
    [ $? = 0 ] || ( 
        echo "Warning: Could not download new cipher list."
    )
}

function reconfigure_network()
{ 
    if [ $TARGET_DEVICE_TYPE != 'last' ]; then 
        configure_network
        get_new_cipher_list
    fi
}


# main

#reconfigure_network
python ptp_init.py reinit
sudo rm -f sniffed.pcap
sudo PATH=$PATH python ptp_controller.py
