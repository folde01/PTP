import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Ether, IP, TCP, sendp
from ptp_network import Network
import os
import sys

#sys.stdout = open('/dev/null', 'w')

class Packet_Sender(object):

    def send_kill_packet(self):
        net = Network()
        kill_packet = Ether(dst=net.get_stop_eth())/IP(dst=net.get_stop_ip())/TCP()
        sendp(kill_packet, iface=net.get_nic_name())
        
    def send_test_packet(self):
        test_packet = Ether(dst='00:00:00:01:02:03')/IP(dst='10.10.10.10')/TCP()
        sendp(test_packet, iface=net.get_nic_name())
