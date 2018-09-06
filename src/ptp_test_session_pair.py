#from scapy.all import rdpcap, PacketList, TCP, Raw
#from scapy.all import *
#from ptp_network import Network
#from ptp_connection_status import Stream_Status, TCP_Status, SSL_Status
#from ptp_tcp_payload import TCP_Payload
#import re

from ptp_session_reassembler import Session_Reassembler 
from ptp_constants import Constants
import unittest

class Test_Session_Pair(unittest.TestCase):
        
    def setUp(self):
        from ptp_session_reassembler import Session_Reassembler

    def tearDown(self):
        pass

    def test_tcp_handshake_seen(self):
        pcap = Constants().TEST_PCAP_DIR + '/tcp-handshake-observed.pcap'
        sr = Session_Reassembler(pcap)
        sp = sr.get_session_pairs().values()[0]
        self.assertTrue(sp._tcp_handshake_is_seen())

    def test_tcp_handshake_missing(self):
        pcap = Constants().TEST_PCAP_DIR + '/tcp-handshake-missing.pcap'
        sr = Session_Reassembler(pcap)
        sp = sr.get_session_pairs().values()[0]
        self.assertFalse(sp._tcp_handshake_is_seen())

    def test_ssl_cli_hello_is_seen(self):
        pass

    def test_ssl_cli_hello_is_not_seen(self):
        pass

    def test_ssl_cli_ccs_is_seen(self):
        pass

    def test_ssl_cli_ccs_is_not_seen(self):
        pass

    def test_ssl_svr_hello_is_seen(self):
        pass

    def test_ssl_svr_hello_is_not_seen(self):
        pass
    
    def test_ssl_svr_ccs_is_seen(self):
        pass

    def test_ssl_svr_ccs_is_not_seen(self):
        pass

    def test_ssl_cipher_is_correct(self):
        pass

    def test_ssl_version_is_correct(self):
        pass

    def test_is_encrypted(self):
        pass

    def test_is_not_encrypted(self):
        pass


if __name__ == '__main__':
    unittest.main()


if __name__ == '__main__':
    unittest.main()

