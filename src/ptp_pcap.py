from scapy.all import rdpcap, PcapWriter 

class Pcap:

    def concatenate_files(self, pcap1, pcap2):
        '''Appends second file's packets onto the first. For creating pcap files used in 
        unit testing.'''

        pkts1 = rdpcap(pcap1)
        pkts1_writer = PcapWriter(pcap1, append=True, sync=True)
        pkts2 = rdpcap(pcap2)

        for pkt in pkts2:
            pkts1_writer.write(pkt)

        pkts1 = rdpcap(pcap1)
