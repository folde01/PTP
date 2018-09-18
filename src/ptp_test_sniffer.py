from ptp_sniffer import Sniffer
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Ether, IP, TCP, sendp, rdpcap, Raw, PacketList, PPP
import unittest
import os

class Test_Sniffer(unittest.TestCase):

    def setUp(self):
        self.pcap_filename = 'sniffed_TEST.pcap'
        if os.path.isfile(self.pcap_filename):
            os.remove(self.pcap_filename)
        self.sniffer = Sniffer(pcap_filename=self.pcap_filename)
        self.test_packet = Ether(dst='0a:0b:0c:0d:0e:0f')/IP(dst='10.20.30.40')/TCP(sport=12345,dport=54321,seq=12345678)/Raw("TCP payload of test packet")

    def tearDown(self):
        self.sniffer.stop()
        if os.path.isfile(self.pcap_filename):
            os.remove(self.pcap_filename)
        
    def test_sniffer_is_not_running_before_starting_it(self):
        self.assertFalse(self.sniffer.is_running())

    def test_start_starts_sniffer(self):
        self.sniffer.start()
        self.assertTrue(self.sniffer.is_running())

    def test_stop_stops_sniffer(self):
        self.sniffer.start()
        self.sniffer.stop()
        self.assertFalse(self.sniffer.is_running())
    
    def test_pcap_file_exists_if_sniffer_has_finished(self):
        self.sniffer.start()
        self.sniffer.stop()
        self.assertTrue(self.sniffer.pcap_file_exists())

    def test_no_pcap_file_if_sniffer_has_not_run(self):
        self.assertFalse(self.sniffer.pcap_file_exists())

    def test_sniffer_detects_correct_number_of_packets(self):
        num_packets = 100000
        pcap_filename = 'test-pcap-files/sniffer_test.pcap'
        dest_eth='0a:0b:0c:0d:0e:0f'
        dest_ip='10.20.30.40'
        src_pt=12345
        dest_pt=54321
        payload="TCP payload of test packet"
        test_packet = Ether(dst=dest_eth) \
                /IP(dst=dest_ip) \
                /TCP(sport=src_pt,dport=dest_pt)\
                /Raw(payload)
        sniffer = Sniffer(pcap_filename=pcap_filename)

        sniffer.start()
        sendp(test_packet, count=num_packets, iface=sniffer._sniff_iface_name)
        sniffer.stop()

        packets = rdpcap(pcap_filename)
        num_packets_sniffed = len(packets)
        debug_msg = 'num_packets_sniffed: {}'.format(num_packets_sniffed)
        self.assertEqual(num_packets_sniffed, num_packets, msg=debug_msg)

        



'''
    def test_test_packet_sent_and_received(self):
        self.sniffer.start()
        Packet_Sender().send_test_packet()
        self.sniffer.stop()
'''


if __name__ == '__main__':
    unittest.main()
