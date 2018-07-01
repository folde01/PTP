import unittest
from scapy.all import TCP, Raw 
from ptp_session_reassembler import Session_Reassembler
import re

class TCP_Payload:
     
    # SSL protocol constants 
    RECORDTYPE_HANDSHAKE =      '16'
    VERSION_SSLV3_0 =           '0300'
    VERSION_TLSV1_0 =           '0301'
    VERSION_TLSV1_1 =           '0302'
    VERSION_TLSV1_2 =           '0303'
    MESSAGETYPE_CLIENTHELLO =   '01'

    def __init__(self, pkt):
        if pkt.haslayer(Raw):
            load = pkt[TCP][Raw].load
            self._load = load.encode('HEX')
        else:
            self._load = None
	
    def get_load(self):
        return self._load

    def is_ssl_client_hello(self):
        try:
            re_client_hello = re.compile(  
                    r'''
                    ^         

                    # SSL record protocol:
                    %s              # handshake record type 
                    (%s|%s|%s|%s)   # SSL version: any of four currently use
                    [0-9a-f]{2}     # message length 

                    # SSL handshake protocol:
                    %s              # ClientHello message type
                    [0-9a-f]{6}     # message length 

                    ''' % (re.escape(self.RECORDTYPE_HANDSHAKE),
                           re.escape(self.VERSION_SSLV3_0),
                           re.escape(self.VERSION_TLSV1_0),
                           re.escape(self.VERSION_TLSV1_1),
                           re.escape(self.VERSION_TLSV1_2),
                           re.escape(self.MESSAGETYPE_CLIENTHELLO)), 
                    re.VERBOSE | re.IGNORECASE)
            position = 0
            match = re_client_hello.search(self.get_load(), position)
            print match
            if match: 
                return True
            else:
                return False
        except TypeError:
            return False

    def is_ssl_client_change_cipher_spec(self):
        return False

    def is_ssl_server_change_cipher_spec(self):
        return False

    



class Test_TCP_Payload(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_is_ssl_hello_request(self):
        pcap = Constants().TEST_PCAP_DIR + '/tcp-handshake-observed.pcap'
        sr = Session_Reassembler(pcap)
        sp = sr.get_session_pairs().values()[0]
        cli_to_svr_session = sp[0]
	cli_pkt_0 = cli_to_svr_session[0] 
	cli_load_0 = TCP_Payload(cli_pkt_0)
        self.assertTrue(cli_load_0.is_ssl_hello_request())
