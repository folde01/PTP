#from scapy.all import rdpcap, PacketList, TCP, Raw
#from scapy.all import *
#from ptp_network import Network
#from ptp_connection_status import Stream_Status, TCP_Status, SSL_Status
#from ptp_tcp_payload import TCP_Payload
#import re


from ptp_session_reassembler import Session_Reassembler 
from ptp_constants import Constants, Is_Encrypted_Enum
import unittest

class Test_Session_Pair(unittest.TestCase):
        
    def setUp(self):
        self.pcap = 'test-pcap-files/ssl-test.pcap'
        cli_ip, cli_pt, svr_ip, svr_pt = ('10.0.2.15', '55083', '104.25.157.13', '443')
        self.stream_with_ssl_handshake = (cli_ip, cli_pt, svr_ip, svr_pt) 
        cli_ip, cli_pt, svr_ip, svr_pt = ('10.0.2.15', '47769', '52.95.132.37', '443')
        self.stream_without_ssl_handshake = (cli_ip, cli_pt, svr_ip, svr_pt) 
        cli_ip, cli_pt, svr_ip, svr_pt = ('10.0.2.15', '33074', '216.58.206.33', '80')
        self.stream_using_http = (cli_ip, cli_pt, svr_ip, svr_pt) 

    def tearDown(self):
        pass

    def test_ssl_cli_hello_is_seen(self):
        print '------------------- test_ssl_cli_hello_is_seen -------------------'
        reassembler = Session_Reassembler(self.pcap)
        pairs = reassembler.get_session_pairs() 
        pair_id = self.stream_with_ssl_handshake
        pair = pairs[pair_id]
        pair._ssl_handshake_client_analysis()
        ssl_status = pair._ssl_status
        cli_hello_is_seen = ssl_status.ssl_cli_hello
        self.assertTrue(cli_hello_is_seen)

    def test_ssl_cli_hello_is_not_seen(self):
        print '------------------- test_ssl_cli_hello_is_seen -------------------'
        reassembler = Session_Reassembler(self.pcap)
        pairs = reassembler.get_session_pairs() 
        pair_id = self.stream_without_ssl_handshake
        pair = pairs[pair_id]
        pair._ssl_handshake_client_analysis()
        ssl_status = pair._ssl_status
        cli_hello_is_seen = ssl_status.ssl_cli_hello
        self.assertFalse(cli_hello_is_seen)


    def test_ssl_cli_ccs_is_seen(self):
        print '------------------- test_ssl_cli_hello_is_seen -------------------'
        reassembler = Session_Reassembler(self.pcap)
        pairs = reassembler.get_session_pairs() 
        pair_id = self.stream_with_ssl_handshake
        pair = pairs[pair_id]
        pair._ssl_handshake_client_analysis()
        ssl_status = pair._ssl_status
        cli_ccs_is_seen = ssl_status.ssl_cli_ccs
        self.assertTrue(cli_ccs_is_seen)

    def test_ssl_cli_ccs_is_not_seen(self):
        print '------------------- test_ssl_cli_hello_is_seen -------------------'
        reassembler = Session_Reassembler(self.pcap)
        pairs = reassembler.get_session_pairs() 
        pair_id = self.stream_without_ssl_handshake
        pair = pairs[pair_id]
        pair._ssl_handshake_client_analysis()
        ssl_status = pair._ssl_status
        cli_ccs_is_seen = ssl_status.ssl_cli_ccs
        self.assertFalse(cli_ccs_is_seen)

    def test_ssl_svr_hello_is_seen(self):
        print '------------------- test_ssl_svr_hello_is_seen -------------------'
        reassembler = Session_Reassembler(self.pcap)
        pairs = reassembler.get_session_pairs() 
        pair_id = self.stream_with_ssl_handshake
        pair = pairs[pair_id]
        pair._ssl_handshake_server_analysis()
        ssl_status = pair._ssl_status
        svr_hello_is_seen = ssl_status.ssl_svr_hello
        self.assertTrue(svr_hello_is_seen)

    def test_ssl_svr_hello_is_not_seen(self):
        print '------------------- test_ssl_svr_hello_is_not_seen -------------------'
        reassembler = Session_Reassembler(self.pcap)
        pairs = reassembler.get_session_pairs() 
        pair_id = self.stream_without_ssl_handshake
        pair = pairs[pair_id]
        pair._ssl_handshake_server_analysis()
        ssl_status = pair._ssl_status
        svr_hello_is_seen = ssl_status.ssl_svr_hello
        self.assertFalse(svr_hello_is_seen)
    
    def test_ssl_svr_ccs_is_seen(self):
        print '------------------- test_ssl_svr_ccs_is_seen -------------------'
        reassembler = Session_Reassembler(self.pcap)
        pairs = reassembler.get_session_pairs() 
        pair_id = self.stream_with_ssl_handshake
        pair = pairs[pair_id]
        pair._ssl_handshake_server_analysis()
        ssl_status = pair._ssl_status
        svr_ccs_is_seen = ssl_status.ssl_svr_ccs
        self.assertTrue(svr_ccs_is_seen)

    def test_ssl_svr_ccs_is_not_seen(self):
        print '------------------- test_ssl_svr_ccs_is_not_seen -------------------'
        reassembler = Session_Reassembler(self.pcap)
        pairs = reassembler.get_session_pairs() 
        pair_id = self.stream_without_ssl_handshake
        pair = pairs[pair_id]
        pair._ssl_handshake_server_analysis()
        ssl_status = pair._ssl_status
        svr_ccs_is_seen = ssl_status.ssl_svr_ccs
        self.assertFalse(svr_ccs_is_seen)

    def test_ssl_cipher_is_correct(self):
        print '------------------- test_ssl_cipher_is_correct -------------------'
        cipher_in_pcap = 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256' 
        reassembler = Session_Reassembler(self.pcap)
        pairs = reassembler.get_session_pairs() 
        pair_id = self.stream_with_ssl_handshake
        pair = pairs[pair_id]
        pair._ssl_handshake_server_analysis()
        ssl_status = pair._ssl_status
        ssl_cipher = ssl_status.ssl_cipher
        self.assertEquals(ssl_cipher, cipher_in_pcap)

    def test_ssl_version_is_correct(self):
        print '------------------- test_ssl_version_is_correct -------------------'
        version_in_pcap = 'TLS 1.2'
        reassembler = Session_Reassembler(self.pcap)
        pairs = reassembler.get_session_pairs() 
        pair_id = self.stream_with_ssl_handshake
        pair = pairs[pair_id]
        pair._ssl_handshake_server_analysis()
        ssl_status = pair._ssl_status
        ssl_version = ssl_status.ssl_version
        self.assertEquals(ssl_version, version_in_pcap)

    def test_is_encrypted(self):
        print '------------------- test_is_encrypted -------------------'
        reassembler = Session_Reassembler(self.pcap)
        pairs = reassembler.get_session_pairs() 
        pair_id = self.stream_with_ssl_handshake
        pair = pairs[pair_id]
        #ssl_status = pair._get_ssl_status()
        stream_status = pair.get_stream_status()
        is_encrypted = stream_status.ssl_status.is_encrypted
        self.assertEquals(is_encrypted, Is_Encrypted_Enum.YES)

    def test_is_not_encrypted(self):
        print '------------------- test_is_not_encrypted -------------------'
        reassembler = Session_Reassembler(self.pcap)
        pairs = reassembler.get_session_pairs() 
        pair_id = self.stream_using_http
        pair = pairs[pair_id]
        #ssl_status = pair._get_ssl_status()
        stream_status = pair.get_stream_status()
        is_encrypted = stream_status.ssl_status.is_encrypted
        self.assertEquals(is_encrypted, Is_Encrypted_Enum.NO)


'''
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
'''

if __name__ == '__main__':
    unittest.main()

