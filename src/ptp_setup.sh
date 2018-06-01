#!/usr/bin/env bash

# host prereqs:

# we need to run virtual interface in promiscuous mode. On hosts running VMWare, run this as root on the host itself:
# chmod a+rw /dev/vmnet0 
# 
# On VirtualBox this can be done in the settings for the network interface of the VM.
 


# VM prerequisites: Ubuntu 16.04 server running in VirtualBox or VMWare, with bridged network and sshd running so this script can be run from the host.

# disable ipv6
if [ `cat /proc/sys/net/ipv6/conf/all/disable_ipv6` == 0 ]; 
then 
	sudo bash -c "echo 'net.ipv6.conf.all.disable_ipv6 = 1' >> /etc/sysctl.conf"
	sudo bash -c "echo 'net.ipv6.conf.default.disable_ipv6 = 1' >> /etc/sysctl.conf"
	sudo bash -c "echo 'net.ipv6.conf.lo.disable_ipv6 = 1' >> /etc/sysctl.conf"
	sudo sysctl -p
fi

# OS updates: 
sudo apt-get update
sudo apt-get -y dist-upgrade
sudo apt-get -y install virtualbox-guest-dkms 

# Dependencies: VPN (pptpd to start with), virtualenv, python 2, pip, scapy, libnids, pynids, flask, mock ...

sudo apt-get install mysql-server
sudo apt-get install pptpd
# todo: finish pptpd


sudo apt-get -y install libnet1-dev

# reboot if required

if [ -f /var/run/reboot-required ]; then
      echo 'Reboot required. Rerun this script after the VM has rebooted.'
      reboot
fi

PTP_HOME=$HOME/ptp
PTP_PREREQS=$PTP_HOME/prereqs

# rm -rf $PTP_HOME
# mkdir -p $PTP_HOME
# mkdir -p $PTP_PREREQS
sudo apt-get update
sudo apt-get install -y python-pip
pip install --upgrade pip
pip install virtualenv


virtualenv --no-site-packages venv
source venv/bin/activate
pip install flask
pip install flask_table
pip install scapy
pip install mock # dev

sudo apt-get install libmysqlclient-dev python-dev
pip install mysqlclient


mkdir -p $PTP_PREREQS

cd $PTP_PREREQS
sudo apt-get -y install libpcap-dev
sudo apt-get install -y pkg-config
sudo apt-get install -y libglib2.0-dev

cd $PTP_PREREQS
git clone https://github.com/MITRECND/pynids.git
cd pynids
python setup.py build
python setup.py install

cd $PTP_PREREQS
git clone https://github.com/CoreSecurity/pcapy.git
cd pcapy
python setup.py install

# run PTP:
export PTP_HOME=~/ptp
cd $PTP_HOME
. venv/bin/activate
git clone https://github.com/folde01/PTP.git
cd PTP
sudo PATH=$PATH python ptp_ui.py
