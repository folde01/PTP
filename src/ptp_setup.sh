#!/usr/bin/env bash

# VM prerequisites: Ubuntu 16.04 server running in VirtualBox, with bridged network and sshd running so this script can be run from the host.

# Dependencies: virtualenv, python 2, pip, scapy, libnids, pynids, flask ...

sudo apt-get update
sudo apt-get -y dist-upgrade
sudo apt-get -y install virtualbox-guest-dkms 

# reboot if required

if [ -f /var/run/reboot-required ]; then
      echo 'Reboot required. Rerun this script after the VM has rebooted.'
      reboot
fi

PTP_HOME=$HOME/ptp

rm -rf $PTP_HOME
sudo apt-get update
sudo apt-get install -y python-pip
pip install virtualenv
mkdir -p $PTP_HOME
cd $PTP_HOME
virtualenv --no-site-packages venv
source venv/bin/activate
pip install flask
pip install scapy

git clone https://github.com/folde01/PTP.git
