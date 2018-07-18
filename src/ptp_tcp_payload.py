import unittest
from scapy.all import TCP, Raw 
from ptp_packet_dissection import Packet_Dissection 
from ptp_constants import Constants
import re

class TCP_Payload(object):
     
    def __init__(self, pkt):
        self._constants = Constants()
        if pkt.haslayer(Raw):
            load = pkt[TCP][Raw].load
            self._load = load.encode('HEX')
        else:
            self._load = None
            print "no raw layer"
        self._dissection = Packet_Dissection()
	
    def get_load(self):
        return self._load

    def range_matches(self, start_byte, num_bytes, hex_str):
        '''Matches a pattern in the hex-encoded-string TCP payload, as per a
        specified byte range. E.g. if a payload started with \x16\x03\x01\x02,
        range_matches(1,2,'0301') would return True.

        Args:
            start_byte (int): start of byte range of TCP payload 
            num_bytes (int): length of byte range, 1 or greater 
            hex_str (str): a string made of digits, representing hex bytes.

        Returns:
            bool: True if the byte range contains the hex string pattern,
            False otherwise

        Raises:
            ValueError: If hex_str is not made of hex digits, or if it doesn't
            represent a byte string of the specified length, or if it isn't
            correctly padded (so must be an even number of hex digits).
        '''

        start_index = 2 * start_byte
        end_index = start_index + (2 * num_bytes)
        hex_str = str(hex_str)

        if (len(hex_str) != 2 * num_bytes) or (len(hex_str) % 2 != 0):
            s = """The hex string (%s) must represent bytes, so it must be an
            even number of hex digits. It must also be of the provided byte
            length (%d)."""  % (hex_str, num_bytes)
            raise ValueError(s)

        try:
            int(hex_str, 16)
        except ValueError:
            s = "Non-hex string given: %s" % hex_str
            raise ValueError(s) 

        return self.get_load()[start_index:end_index] == hex_str 


    def range_matches_any(self, start_byte, num_bytes, hex_strs):
        '''Works like range_matches but takes a collection of hex string patterns
        to check for a match, and returns the one that matches, otherwise None.

        Args:
            start_byte (int): start of byte range of TCP payload 
            num_bytes (int): length of byte range 
            hex_strs (str): a collection of strings made of digits, representing hex bytes.

        Returns:
            str: The match, if there was one, otherwise None.  
        '''
        start_index = 2 * start_byte
        end_index = start_index + (2 * num_bytes)
        hex_strs = [str(hex_str) for hex_str in hex_strs] 

        for hex_str in hex_strs:
            if (len(hex_str) != 2 * num_bytes) or (len(hex_str) % 2 != 0):
                s = """
                The hex string (%s) must represent bytes, so it must be an
                even number of hex digits. It must also be of the provided byte
                length (%d)."""  % (hex_str, num_bytes)
                raise ValueError(s)
            try:
                int(hex_str, 16)
            except ValueError:
                s = "Non-hex string given: %s" % hex_str
                raise ValueError(s) 

            print start_index, end_index
            if self.get_load()[start_index:end_index] == hex_str:
                return hex_str

        return None


    def is_protocol_handshake(self):
        '''
        Returns:
            bool: True if SSL handshake record type, False otherwise. 
        '''
        const = self._constants.ssl
        start_byte = const['start_bytes']['RECORD_PROTOCOL']
        num_bytes = const['lengths']['RECORD_PROTOCOL']
        hex_str = const['protocols']['HANDSHAKE']
        return self.range_matches(start_byte, num_bytes, hex_str)

    def is_protocol_change_cipher_spec(self):
        const = self._constants.ssl
        start_byte = const['start_bytes']['RECORD_PROTOCOL']
        num_bytes = const['lengths']['RECORD_PROTOCOL']
        hex_str = const['protocols']['CHANGE_CIPHER_SPEC']
        return self.range_matches(start_byte, num_bytes, hex_str)

    def is_version_valid(self):
        const = self._constants.ssl
        valid_ssl_versions = const['versions'].values()
        start_byte = const['start_bytes']['VERSION']
        num_bytes = const['lengths']['VERSION']
        return self.range_matches_any(start_byte, num_bytes, valid_ssl_versions)

    def is_message_client_hello(self):
        const = self._constants.ssl
        start_byte = const['start_bytes']['HANDSHAKE']
        num_bytes = const['lengths']['HANDSHAKE']
        hex_str = const['handshake_messages']['CLIENT_HELLO']
        return self.range_matches(start_byte, num_bytes, hex_str)

    def is_message_change_cipher_spec(self):
        const = self._constants.ssl
        start_byte = const['start_bytes']['CHANGE_CIPHER_SPEC']
        num_bytes = const['lengths']['CHANGE_CIPHER_SPEC']
        hex_str = const['ccs_messages']['CHANGE_CIPHER_SPEC']
        return self.range_matches(start_byte, num_bytes, hex_str)

    def is_payload_client_hello(self):
        return self.is_protocol_handshake() and \
                self.is_version_valid() and \
                self.is_message_client_hello()

    def is_payload_client_change_cipher_spec(self):
        return is_protocol_change_cipher_spec() and \
                self.is_version_valid() and \
                self.is_message_change_cipher_spec()


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
        pass

    def tearDown(self):
        pass

    def test_is_ssl_client_hello(self):
        from ptp_session_reassembler import Session_Reassembler
        pcap = Constants().TEST_PCAP_DIR + '/test1.pcap'
        sr = Session_Reassembler(pcap)
        sp_index = 0
        sp = sr.get_session_pairs().values()[sp_index]
        cli_to_svr_session = sp._cli_to_svr
        cli_hello_pkt_index = 2
        pkt = cli_to_svr_session[cli_hello_pkt_index]
        print repr(pkt)
	flight1_payload = TCP_Payload(pkt)
        self.assertTrue(flight1_payload.is_ssl_client_hello())


if __name__ == '__main__':
    unittest.main()

