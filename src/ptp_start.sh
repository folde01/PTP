#!/usr/bin/env bash

function get_new_cipher_list()
{ 
    echo "Configuring cipher list."
    ./ptp_cipher_list.sh > /dev/null 2>&1
    [ $? = 0 ] || ( 
        echo "Warning: Could not download new cipher list."
    )
}

function exit_if_down_tap_interface_exists()
{ 
    # tap interface needs to be up for virtual device to work, and 
    # we shouldn't see a tap interface configured if we are using
    # a physical TD.
    TAP_IFACE="tap0"
    ip link show dev $TAP_IFACE >/dev/null 2>&1 
    if [ $? -eq 0 ]; then
        TAP_IFACE_STATE=`ip link show dev $TAP_IFACE | grep $TAP_IFACE | awk '{print $9}'`
        if [ $TAP_IFACE_STATE = "DOWN" ]; then
            echo "$TAP_IFACE found in DOWN state: not starting PTP"
            exit 1
        fi
    fi
}



# main

exit_if_down_tap_interface_exists
get_new_cipher_list
python ptp_init.py reinit
sudo rm -f sniffed.pcap
sudo PATH=$PATH python ptp_controller.py
