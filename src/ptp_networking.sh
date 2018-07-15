#!/usr/bin/env bash

# TODO: Enable emulator or physical TD to be used without manually changing network.

# If running on Ubuntu 16.04 VM, and physical TD connecting via PPTP over wifi:

#sudo iptables -t nat -A POSTROUTING -o enp0s3 -j MASQUERADE && iptables-save
#sudo service pptpd restart


# If we need an emulator, and running on Ubuntu 16.04 physical, with emulator TD running in QEMU, connecting via tap interface.
# credit to https://www.cypherpunk.at/2017/08/monitoring-android-emulator-network-traffic/

# TODO: use e.g. pyroute2

#DNS_SERVER=192.168.1.1 # home router is DNS server - works
#DNS_SERVER=10.62.23.254 # uni - broken, because I didn't realize at the time this should actually be uni DNS server.
DNS_SERVER=192.168.43.1 # hotspot - works

sudo ip link delete tap0 > /dev/null 2>&1
sudo iptables -t nat -F

sudo ip tuntap add name tap0 mode tap
#sudo ip tuntap show
sudo ip link set tap0 up

# tap0 needs an IP on 10.0.2.0/24 for the host:
sudo ip address add 10.0.2.2/24 dev tap0

# tap0 also needs to listen on 10.0.2.3, the first DNS server of the emulator.
# iptables is used below to get emulator DNS requests to the host's DNS server.
sudo ip address add 10.0.2.3/24 dev tap0

#ip a | grep wlp3s0
#sudo nmcli dev show wlp3s0
#sudo sysctl net.ipv4.conf.all.forwarding # set to 1
# TODO: use e.g. python-iptables

# Now we set up the host to route traffic and do NAT.
# See https://www.karlrupp.net/en/computer/nat_tutorial

# Rule 1 (IP masqerade): if a packet received by the host A) comes from a client on 10.0.2.0/24 (which would arrive on tap0, 
# as per iproute2 commands above, and the fact that the emulator uses 10.0.2.15 by default)
# and B) its destination is an IP address that, by the host's routing tables (hence use of the POSTROUTING chain), should be routed via interface wlp3s0,
# then change the packet's source IP to be the IP of wlp3s0 (the host's outgoing interface) and keep track of this IP address translation
# so that reply packets can be have their destination address changed to be the address of the client. 
sudo iptables -t nat -A POSTROUTING -s 10.0.2.0/24 -o wlp3s0 -j MASQUERADE

# Rule 2 (DNS):
# change destination IP to $DNS_SERVER if destination is  10.0.2.3, which is the emulator's first DNS server, so this rule makes emulator DNS requests go
# somewhere which can actually answer those queries.
# TODO: get this dynamically by looking up the host's DNS server.
sudo iptables -t nat -A PREROUTING -d 10.0.2.3 -j DNAT --to-destination $DNS_SERVER
