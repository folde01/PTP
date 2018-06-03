from scapy.all import IP, TCP

class Pcap:
    def __init__(self. pcap_filename='sniffed.pcap'):
        self._pcap_filename = pcap_filename

    def lo_and_hi_timestamps(self, stream):
        # sometimes cli will be src, sometimes dst. We care about when it is src.
        lo_ts = None 
        hi_ts = None 
        pkts_from_cli = (pkt for pkt in pkts if IP in pkt and pkt[IP].src = stream.cli_ip)

        for pkt in pkts_from_cli: 
            if lo_ts is None or pkt.time < lo_ts:
                lo_ts = pkt.time

            if hi_ts is None or pkt.time > hi_ts:
                hi_ts = pkt.time

        return lo_ts, hi_ts








