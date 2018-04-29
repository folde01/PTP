import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Ether, IP, TCP, sendp

class PacketSender:

    def send_kill_packet(self):
        kill_packet = Ether(dst='00:00:00:03:02:01')/IP(dst='10.11.12.13')/TCP()
        sendp(kill_packet)
        
    def send_test_packet(self):
        test_packet = Ether(dst='00:00:00:01:02:03')/IP(dst='10.10.10.10')/TCP()
        sendp(test_packet)




