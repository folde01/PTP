import unittest
from ptp_session_reassembler import Session_Reassembler
from scapy.all import rdpcap, PacketList, Ether, IP, TCP, Raw


class Test_Session_Reassembler(unittest.TestCase):
    """Unit tests for PTP Session_Reassembler class"""

    def test_only_duplicate_ack_removed(self):
        """Given a PacketList with three packets, only the duplicate should be removed.
        The other two should remain.
        Duplicates: a pair of ACK packets (ACK flag set, same SEQ and ACK numbers)
        Other: SYN packet (SYN flag set)
        """
        non_dup = Ether()/IP()/TCP(flags='S', seq=0, ack=0)
        ack1 = Ether()/IP()/TCP(flags='A', seq=1, ack=1)
        ack2 = Ether()/IP()/TCP(flags='A', seq=1, ack=1)
        pkts = PacketList([non_dup, ack1, ack2])        
        sr = Session_Reassembler()
        deduped_pkts = sr._remove_duplicate_packets(pkts)
        self.assertTrue(deduped_pkts[0][TCP].flags == 'S') 
        self.assertTrue(len(deduped_pkts) == 2)

    def test_only_duplicate_data_removed(self):
        """Given a PacketList with three packets, only the duplicate should be removed.
        The other two should remain.
        Duplicates: a pair of data packets (PUSH and ACK flags set, same SEQ and ACK numbers)
        Other: SYN packet (SYN flag set)
        """
        non_dup = Ether()/IP()/TCP(flags='S', seq=0, ack=0)
        data1 = Ether() \
                /IP() \
                /TCP(flags='PA', seq=10, ack=11, chksum=0xccfe ) \
                /Raw(load='abc') 
        data2 = Ether() \
                /IP() \
                /TCP(flags='PA', seq=10, ack=11, chksum=0xccfe ) \
                /Raw(load='abc') 
        pkts = PacketList([non_dup, data1, data2])        
        sr = Session_Reassembler()
        deduped_pkts = sr._remove_duplicate_packets(pkts)
        self.assertTrue(deduped_pkts[0][TCP].flags == 'S') 
        self.assertTrue(len(deduped_pkts) == 2)


    def test_only_duplicate_syn_removed(self):
        """Given a PacketList with three packets, only the duplicate should be removed.
        The other two should remain.
        Duplicates: a pair of SYN packets (SYN flag set, same SEQ and ACK numbers)
        Other: ACK packet (ACK flag set)
        """
        syn1 = Ether()/IP()/TCP(flags='S', seq=0, ack=0)
        syn2 = Ether()/IP()/TCP(flags='S', seq=0, ack=0)
        non_dup = Ether()/IP()/TCP(flags='A', seq=1, ack=1)
        pkts = PacketList([syn1, syn2, non_dup])        
        sr = Session_Reassembler()
        deduped_pkts = sr._remove_duplicate_packets(pkts)
        self.assertTrue(deduped_pkts[-1][TCP].flags == 'A') 
        self.assertTrue(len(deduped_pkts) == 2)


    def test_only_duplicate_synack_removed(self):
        """Given a PacketList with three packets, only the duplicate should be removed.
        The other two should remain.
        Duplicates: a pair of SYN/ACK packets (SYN and ACK flag set, same SEQ and ACK numbers)
        Other: ACK packet (ACK flag set)
        """
        synack1 = Ether()/IP()/TCP(flags='SA', seq=0, ack=1)
        synack2 = Ether()/IP()/TCP(flags='SA', seq=0, ack=1)
        non_dup = Ether()/IP()/TCP(flags='A', seq=10, ack=11)
        pkts = PacketList([synack1, synack2, non_dup])        
        sr = Session_Reassembler()
        deduped_pkts = sr._remove_duplicate_packets(pkts)
        self.assertTrue(deduped_pkts[-1][TCP].flags == 'A') 
        self.assertTrue(len(deduped_pkts) == 2)

if __name__ == '__main__':
    unittest.main()
