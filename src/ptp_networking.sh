#!/usr/bin/env bash

# TODO: Enable emulator or physical TD to be used without manually changing network.

# If running on Ubuntu 16.04 VM, and physical TD connecting via PPTP over wifi:

#sudo iptables -t nat -A POSTROUTING -o enp0s3 -j MASQUERADE && iptables-save
#sudo service pptpd restart


# If we need an emulator, and running on Ubuntu 16.04 physical, with emulator TD running in QEMU, connecting via tap interface.
# credit to https://www.cypherpunk.at/2017/08/monitoring-android-emulator-network-traffic/

# TODO: detect DNS server automatically 
NAT_GATEWAY=192.168.1.1 # home router
#NAT_GATEWAY=10.62.23.254 # uni - this is incorrect
#NAT_GATEWAY=192.168.43.1 # hotspot

sudo ip link delete tap0 > /dev/null 2>&1
sudo iptables -t nat -F

sudo ip tuntap add name tap0 mode tap
#sudo ip tuntap show
sudo ip link set tap0 up
sudo ip address add 10.0.2.2/24 dev tap0
sudo ip address add 10.0.2.3/24 dev tap0
#ip a | grep wlp3s0
#sudo nmcli dev show wlp3s0
#sudo sysctl net.ipv4.conf.all.forwarding # set to 1
# TODO: use e.g. python-iptables
sudo iptables -t nat -A POSTROUTING -s 10.0.2.0/24 -o wlp3s0 -j MASQUERADE
sudo iptables -t nat -A PREROUTING -d 10.0.2.3 -j DNAT --to-destination $NAT_GATEWAY
