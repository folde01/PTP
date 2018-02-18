import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import * 
import threading


class Sniffer:

    def __init__(self, pcap_filename='sniffed.pcap'):
        self._pcap_filename = pcap_filename 
        self._packets = None


    def start(self):
        sniffer_thread = threading.Thread(target=self._run_sniffer_thread)
        sniffer_thread.daemon = True
        sniffer_thread.start()


    def _run_sniffer_thread(self):
        self._packets = sniff(filter='ip', stop_filter=self.stopfilter)


    def stopfilter(self, kill_packet):
        if kill_packet[IP].dst == '10.10.10.10':
            return True
        else:
            return False


    def stop(self):
        self._send_kill_packet()


    def write_pcap(self):
        wrpcap(self._pcap_filename, self._packets)


    def pcap_filename(self):
        return self._pcap_filename 


    def _send_kill_packet(self):
        send(IP(dst='10.10.10.10'))
