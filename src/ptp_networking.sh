#!/usr/bin/env bash

# This script sets up the networking for a virtual or physical 
# Target Device for PTP, or for testing using the loopback device.
# See usage() function below for instructions. 

DEVICE_TYPE="$1"
CONFIG_FILE="ptp_network_conf.py"

function usage()
{
	echo "Usage: $0 <virtual|physical>"
}

if [ $# -ne 1 ] || ( [ $DEVICE_TYPE != 'virtual' ] && \
	[ $DEVICE_TYPE != 'physical' ] && [ $DEVICE_TYPE != 'physical' ]); then
	usage
	exit 1
fi

# enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1 > /dev/null

GATEWAY_IFACE=$(iw dev | grep Interface | awk '{print $2}')
SNIFF_IFACE=""

function check_internet()
{
	echo "Checking Internet connectivity..."
	ping -W2 -c2 www.google.com > /dev/null 2>&1
}
	
function configure_networking_for_virtual_device()
{
	echo "Configuring networking for virtual Target Device."

	# Shutting down pptpd in case previously using physical device
	sudo service pptpd stop

	# If we need an emulator, and running on Ubuntu 16.04 physical, with emulator TD running in QEMU, connecting via tap interface.
	# credit to https://www.cypherpunk.at/2017/08/monitoring-android-emulator-network-traffic/

	SNIFF_IFACE="tap0"
	DNS_SERVER=$(nmcli device show $GATEWAY_IFACE | grep IP4.DNS | awk '{print $2}')

	sudo ip link delete $SNIFF_IFACE > /dev/null 2>&1
	# Flush NAT table
	sudo iptables -t nat -F

	# Configure and bring up tap interface	
	sudo ip tuntap add name $SNIFF_IFACE mode tap
	#sudo ip tuntap show
	sudo ip link set $SNIFF_IFACE up

	# $SNIFF_IFACE needs an IP on 10.0.2.0/24 (emulator net) for the host:
	sudo ip address add 10.0.2.2/24 dev $SNIFF_IFACE

	# $SNIFF_IFACE also needs to listen on 10.0.2.3, the first DNS server of the emulator.
	# iptables is used below to get emulator DNS requests to the host's DNS server.
	sudo ip address add 10.0.2.3/24 dev $SNIFF_IFACE

	# Now we set up the host to route traffic and do NAT.
	# See https://www.karlrupp.net/en/computer/nat_tutorial

	# This needs two rules:

	# Rule 1 (IP masqerade): if a packet received by the host A) comes from a 
	# client on 10.0.2.0/24 (which would arrive on $SNIFF_IFACE, 
	# as per iproute2 commands above, and the fact that the emulator uses 10.0.2.15 by default)
	# and B) its destination is an IP address that, by the host's 
	# routing tables (hence use of the POSTROUTING chain), should be routed via interface wlp3s0, then: 
	# change the packet's source IP to be the IP of wlp3s0 (the host's outgoing 
	# interface) and keep track of this IP address translation
	# so that reply packets can be have their destination address changed to be the address of the client. 
	sudo iptables -t nat -A POSTROUTING -s 10.0.2.0/24 -o $GATEWAY_IFACE -j MASQUERADE

	# Rule 2 (DNS):
	# change destination IP to $DNS_SERVER if destination is 10.0.2.3,
	# which is the emulator's first DNS server, so this rule makes emulator DNS requests go
	# somewhere which can actually answer those queries.

	sudo iptables -t nat -A PREROUTING -d 10.0.2.3 -j DNAT --to-destination $DNS_SERVER
	
}

function configure_networking_for_physical_device()
{
	echo "Configuring networking for physical Target Device."
	#SNIFF_IFACE="ppp0"
	SNIFF_IFACE=$GATEWAY_IFACE
	sudo iptables -t nat -F
	sudo iptables -t nat -A POSTROUTING -o $GATEWAY_IFACE -j MASQUERADE && iptables-save
	sudo service pptpd restart
	echo 
}

function configure_networking_for_loopback_testing()
{
	echo "Configuring networking for loopback testing."
	SNIFF_IFACE="lo"
	sudo iptables -t nat -F
	sudo service pptpd stop 
}


check_internet
if [ $? != 0 ]; then
	echo "No Internet connectivity using Wifi interface. PTP won't work without this." 
	echo "Giving up."
	exit 1
fi


case "$DEVICE_TYPE" in
	"virtual")
		configure_networking_for_virtual_device
		;;
	"physical")
		configure_networking_for_physical_device
		GATEWAY_IFACE_IP_ADDR=`ip addr show $GATEWAY_IFACE | grep "inet " | awk '{print $2}' | cut -d/ -f1`
		echo "Connect your physical Target Device's VPN to this IP address:"
		echo $GATEWAY_IFACE_IP_ADDR
		;;
	"loopback")
		configure_networking_for_loopback_testing
		;;
esac

cat /dev/null > $CONFIG_FILE
(
echo "# DO NOT EDIT - CREATED DYNAMICALLY"
echo "gateway_iface = '$GATEWAY_IFACE'"
echo "sniff_iface = '$SNIFF_IFACE'"
) >> $CONFIG_FILE


