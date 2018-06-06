from scapy.all import IP, TCP, rdpcap
from ptp_network import Network
from ptp_constants import Constants


class Pcap:
    def __init__(self, pcap_filename=Constants().DEFAULT_PCAP_FILENAME):
        self._pcap_filename = pcap_filename
        self._pkts = None
        self._cli_ip = Network().get_cli_ip()

    def _read_pcap_file(self):
        if self._pkts is None:
            self._pkts = rdpcap(self._pcap_filename)

    def get_quads(self):
        self._read_pcap_file()
        quads = []

        for pkt in self._pkts:
            quad = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)

            if quad not in quads:
                quads.append(quad)

        return quads

    def lo_and_hi_timestamps(self, quad):
        self._read_pcap_file()
        lo_ts = None 
        hi_ts = None 
        cli_ip, cli_pt, svr_ip, svr_pt = quad

        for pkt in self._pkts: 
            cur_quad = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
            
            if quad == cur_quad:

                if lo_ts is None or pkt.time < lo_ts:
                    lo_ts = pkt.time

                if hi_ts is None or pkt.time > hi_ts:
                    hi_ts = pkt.time

        return lo_ts, hi_ts

    def _get_cli_as_src_quads(self):
        quads = self.get_quads()
        return [ quad for quad in quads if quad[0] == self._cli_ip ]
