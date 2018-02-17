import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sniff, wrpcap 

class Sniffer:

    def start(self):
        packets = sniff(count=100)
        wrpcap('sniffed.pcap', packets)

    def stop(self):
        pass

    def pcap_filename(self):
        pass
