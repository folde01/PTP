import unittest
from scapy.all import TCP, Raw 
from ptp_packet_dissection import Packet_Dissection 
import re

class TCP_Payload(object):
     
    # SSL protocol constants 
    RECORDTYPE_HANDSHAKE =      '16'
    VERSION_SSLV3_0 =           '0300'
    VERSION_TLSV1_0 =           '0301'
    VERSION_TLSV1_1 =           '0302'
    VERSION_TLSV1_2 =           '0303'
    MESSAGETYPE_CLIENTHELLO =   '01'
    MESSAGETYPE_SERVERHELLO =   '02'

    def __init__(self, pkt):
        if pkt.haslayer(Raw):
            load = pkt[TCP][Raw].load
            self._load = load.encode('HEX')
        else:
            self._load = None
        self._dissection = Packet_Dissection()
	
    def get_load(self):
        return self._load

    def get_dissection(self):
        return self._dissection

    def dissect_first_flight(self):
        return self._dissection

    def dissect_second_flight(self):
        return self._dissection

    def dissect_third_flight(self):
        return self._dissection

    def dissect_fourth_flight(self):
        return self._dissection

    def dissect_ssl_client_hello(self):
        '''
        First bytes of an example payload which results in True: 
        16030100df010000db0303ad188de0518a4a1df27f3bf0af67...

        We use the hex dump of bytes as it makes counting easier because the
        protocol field lengths are specified as numbers of bytes.

        Breakdown:

        ** Record protocol layer **
        16          1B - type of Record Protocol record, here handshake
        0301        2B - SSL version for backwards compatibility with older servers.
                        (see RFC 5246, p88)
        00df        2B - length of Record Protocol record
        
        ** Handshake layer **
        01          1B - contains Client Hello message - stop here for now.

        Credit for SSL record and handshake protocol analysis to Ristic, 2015 and
        http://blog.fourthbit.com/2014/12/23/traffic-analysis-of-an-ssl-slash-tls-session
        '''


        re_client_hello = re.compile(  
                r'''
                ^(
                # SSL record protocol:
                %s              # handshake record type 
                (%s|%s|%s|%s)  # SSL version: any of four currently use
                [0-9a-f]{4}     # message length 

                # SSL handshake protocol:
                %s              # ClientHello message type
                )
                ''' % (re.escape(self.RECORDTYPE_HANDSHAKE),
                       re.escape(self.VERSION_SSLV3_0),
                       re.escape(self.VERSION_TLSV1_0),
                       re.escape(self.VERSION_TLSV1_1),
                       re.escape(self.VERSION_TLSV1_2),
                       re.escape(self.MESSAGETYPE_CLIENTHELLO),
                       ), 
                re.VERBOSE | re.IGNORECASE)

        match = re_client_hello.match(self.get_load())
        print "match:", match, "groups:", match.groups()

        dissection = self.get_dissection()
        dissection.is_ssl_client_hello = bool(match)

    def is_ssl_server_hello(self):
        '''
        First bytes of an example payload which results in True: 
        16030300500200004c0303069b55b5d30d36f27ca3e5b3b54d571b1ba48aab4c89d9e0da75a6f65d01a27500c02f...

        Breakdown:

        ** Record protocol layer **
        16          1B - type of Record Protocol record, here handshake
        0303        2B - SSL version for backwards compatibility with older servers.
                        (see RFC 5246, p88)
        0050        2B - length of Record Protocol record
        
        ** Handshake layer **
        02          1B - indicates Server Hello message
        00004c      3B - message length
        0303        2B - SSL version
        069b..a275  32B - random
        00          1B - session ID length
        c02f        2B - negotiated cipher suite 

        Credit for SSL record and handshake protocol analysis to Ristic, 2015 and
        http://blog.fourthbit.com/2014/12/23/traffic-analysis-of-an-ssl-slash-tls-session
        '''
        
        re_server_hello = re.compile(  
                r'''
                ^(
                # SSL record protocol:
                %s              # handshake record type 
                (%s|%s|%s|%s)   # SSL version: any of four currently use
                [0-9a-f]{4}     # message length 

                # SSL handshake protocol:
                %s              # ServerHello message type
                [0-9a-f]{6}     # message length 
                (%s|%s|%s|%s)   # SSL version: any of four currently use
                [0-9a-f]{64}    # random 
                00              # Session ID length - assume 0 for now 
                ([0-9a-f]{4})   # cipher 
                )
                ''' % (re.escape(self.RECORDTYPE_HANDSHAKE),
                       re.escape(self.VERSION_SSLV3_0),
                       re.escape(self.VERSION_TLSV1_0),
                       re.escape(self.VERSION_TLSV1_1),
                       re.escape(self.VERSION_TLSV1_2),
                       re.escape(self.MESSAGETYPE_SERVERHELLO),
                       ), 
                re.VERBOSE | re.IGNORECASE)

        match = re_server_hello.match(self.get_load())
        print "match:", match, "groups:", match.groups()

        dissection = self.get_dissection()
        dissection.is_ssl_server_hello = bool(match)

    def is_ssl_client_change_cipher_spec(self):
        return False

    def is_ssl_server_change_cipher_spec(self):
        return False

    def _get_load_with_guide(self):
        '''Handy way of indexing text, credit to PYMOTW'''
        text = self.get_load()[:100]
        print ''.join(str(i/10 or ' ') for i in range(len(text)))
        print ''.join(str(i%10) for i in range(len(text)))
        print text
    
class Test_TCP_Payload(unittest.TestCase):

    def setUp(self):
        from ptp_session_reassembler import Session_Reassembler

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
