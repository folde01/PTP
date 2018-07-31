#from scapy.all import rdpcap, PacketList, TCP, Raw
from scapy.all import *
from ptp_network import Network
from ptp_constants import Constants
from ptp_connection_status import Stream_Status, TCP_Status, SSL_Status
import unittest
from ptp_tcp_payload import TCP_Payload
import re

class Session_Pair(object):

    def __init__(self, cli_to_svr, svr_to_cli):
        self._cli_to_svr = cli_to_svr
        self._svr_to_cli = svr_to_cli
        self._stream_status = None
        self._tcp_status = None
        self._ssl_status = SSL_Status()
	self._const = Constants() 

    def get_stream_status(self):
        """
        Returns: 
            A Stream object containing the full analysis of the session pair.
            This has all the info we need for the stream database.
        """

        stream_status = Stream_Status(tcp_status=self._get_tcp_status(),
                                      ssl_status=self._get_ssl_status())

        return stream_status


    def _get_tcp_status(self):
        """
        Returns: 
            A TCP_Status object containing the TCP analysis of the session pair.
        """

        if self._tcp_status is not None:
            return self._tcp_status

        cli_to_svr_session = self._cli_to_svr 
        svr_to_cli_session = self._svr_to_cli 

        try:
            cli_ip = cli_to_svr_session[0]['IP'].src
            cli_pt = cli_to_svr_session[0]['TCP'].sport
        except TypeError:
            cli_ip = svr_to_cli_session[0]['IP'].dst
            cli_pt = svr_to_cli_session[0]['TCP'].dport

        try:
            svr_ip = svr_to_cli_session[0]['IP'].src
            svr_pt = svr_to_cli_session[0]['TCP'].sport
        except TypeError:
            svr_ip = cli_to_svr_session[0]['IP'].dst
            svr_pt = cli_to_svr_session[0]['TCP'].dport

        bytes_to_svr = self._get_session_payload_size(cli_to_svr_session)
        bytes_to_cli = self._get_session_payload_size(svr_to_cli_session)
        ts_first_pkt, ts_last_pkt = self._get_start_and_end_ts()

        # Assumes for now that TCP Fast Open is not used, so Client Hello is sent in
        # client's third packet.

	tcp_status = TCP_Status(cli_ip=cli_ip, cli_pt=int(cli_pt), svr_ip=svr_ip,
                svr_pt=int(svr_pt), bytes_to_cli=bytes_to_cli,
                bytes_to_svr=bytes_to_svr, ts_first_pkt=float(ts_first_pkt),
                ts_last_pkt=float(ts_last_pkt))

        self._tcp_status = tcp_status
        return tcp_status
 

    def _get_session_payload_size(self, session):
        """
        Args:
            session (PacketList): Scapy packet list representing one direction of
            TCP connection.
        Returns:
            int: size of total TCP payload for all packets in bytes
        """
        if session is None:
            return 0
        size = 0
        for pkt in session:
            size += len(pkt[TCP].payload)
        return size


    def _get_start_and_end_ts(self):
        """returns two-tuple containing lowest and highest timestamps in Epoch seconds, in microseconds.
        returns None if session is None"""

	cli_to_svr_session = self._cli_to_svr
	svr_to_cli_session = self._svr_to_cli

        if cli_to_svr_session and svr_to_cli_session:
            lowest_ts_cli_to_svr = min([pkt.time for pkt in cli_to_svr_session])
            highest_ts_cli_to_svr = max([pkt.time for pkt in cli_to_svr_session])
            lowest_ts_svr_to_cli = min([pkt.time for pkt in svr_to_cli_session])
            highest_ts_svr_to_cli = max([pkt.time for pkt in svr_to_cli_session])
            lowest_ts = min(lowest_ts_cli_to_svr, lowest_ts_svr_to_cli)
            highest_ts = max(highest_ts_cli_to_svr, highest_ts_svr_to_cli)
        elif cli_to_svr_session:
            lowest_ts = min([pkt.time for pkt in cli_to_svr_session])
            highest_ts = max([pkt.time for pkt in cli_to_svr_session])
        else:
            lowest_ts = min([pkt.time for pkt in svr_to_cli_session])
            highest_ts = max([pkt.time for pkt in svr_to_cli_session])

        return (lowest_ts, highest_ts)


    def _get_pkt_payload_length(self, pkt):
        return len(pkt[TCP].payload)


    def _get_ssl_status(self):
        """Examine use (or otherwise) of SSL protocol.

        Returns:
            SSL_Status object containing details of SSL use.
        """
        self._ssl_handshake_client_analysis()
        self._ssl_handshake_server_analysis()
        #self._ssl_tunnel_analysis()
        #self._tcp_close_analysis()
        return self._ssl_status 


    def _get_load(self, pkt):
        '''
        Args:
            pkt (scapy.all.Packet)
        Returns:
            str: TCP payload of a single packet as a string of hex digits,
                from Raw layer of scapy packet.
        Raises:
            TypeError: If packet has no payload.
        '''
        if pkt.haslayer(Raw):
            load = pkt[TCP][Raw].load
            return load.encode('HEX')
        else:
            raise TypeError("Packet has no payload.")  


    def _ssl_handshake_client_analysis(self):
        status = self._ssl_status
	const = self._const.ssl
	pkt_seq = self._cli_to_svr

        if pkt_seq is None:
            print "cli_to_svr is None"
            return

	pkt_seq_load = ''

        # First two packets should be enough in most cases but we increase 
	# it to account for any TCP segmentation or use of client authentication.
        first_n_packets = 4     

	num_pkts_with_payload = [p.haslayer(Raw) for p in pkt_seq].count(True)

        # concatenate payloads of first packets
	if num_pkts_with_payload < first_n_packets:
            pkt_seq_load = ''.join([self._get_load(p) for p in pkt_seq if p.haslayer(Raw)])
        else:
            for i in range(0, first_n_packets+1):
                p = pkt_seq[i]
                if p.haslayer(Raw):
                    pkt_seq_load += self._get_load(p) 
            
        #print "pkt_seq_load:", pkt_seq_load

        # The payload matches a regex if it has both client hello and change cipher
        # suite messages (in that order, with any bytes in between).
	regex = re.compile(
	    r'''
	    ^

            # client hello match group
            (

                # RECORD layer:
                16	            # 16: handshake sub-protocol		
                030[0-3]        # 0300: SSL 3.0, 0301: TLS 1.0, 0302: TLS 1.1, 0303: TLS 1.2
                [0-9a-f]{4}     # 2-byte message length

                # HANDSHAKE layer:
                01              # 01: client hello message
	    )

            # anything-in-between match group 
	    [0-9a-f]*     # Any hex digits

            # change cipher suite match group
	    (
                14              # 14: change cipher suite sub-protocol
                030[0-3]        # 0300: SSL 3.0, 0301: TLS 1.0, 0302: TLS 1.1, 0303: TLS 1.2 
                [0-9a-f]{4}     # 2-byte message length 
                01              # 01: change cipher suite message
	    ) 
	    ''', re.VERBOSE | re.IGNORECASE)

	match = regex.match(pkt_seq_load)

        if match:
            groups = match.groups()
            #print "groups:", groups
            client_hello_group_index = 0
            ccs_group_index = 1
            self._ssl_status.ssl_cli_hello = bool(groups[client_hello_group_index]) 
            #print "show:", self._ssl_status.show()
            self._ssl_status.ssl_cli_ccs = bool(groups[ccs_group_index])


    def _ssl_handshake_server_analysis(self):
	const = self._const.ssl
	pkt_seq = self._svr_to_cli

        if pkt_seq is None:
            print "svr_to_cli is None"
            return
        
	pkt_seq_load = ''

        '''
        The first two loaded packets is not enough as we must account for any TCP
        segmentation or use of client authentication. Setting it too high means we 
        waste time searching payloads unlikely to contain anything we need.
        '''
        first_n_packets = 8

        num_pkts_with_payload = [p.haslayer(Raw) for p in pkt_seq].count(True)


        # concatenate payloads of first packets
	if num_pkts_with_payload < first_n_packets:
            pkt_seq_load = ''.join([self._get_load(p) for p in pkt_seq if p.haslayer(Raw)])
        else:
            for i in range(0, first_n_packets+1):
                p = pkt_seq[i]
                if p.haslayer(Raw):
                    pkt_seq_load += self._get_load(p) 
            
        print "pkt_seq_load:", pkt_seq_load

        '''
        The payload if it has both server hello and change cipher
        suite messages (in that order, with any bytes in between). This has to 
        be done in parts. The first part ends with the session ID length,
        as we need to know what it is before proceeding. We grab the agreed 
        SSL version from the handshake sub-protocol layer along the way.
        '''

        re_record_layer =  r'''
            ^(
                16	        # 16: handshake sub-protocol		
                030[0-3]        # 0300: SSL 3.0, 0301: TLS 1.0, 0302: TLS 1.1, 0303: TLS 1.2
                [0-9a-f]{4}     # 2-byte message length
            )
            '''

        re_handshake_layer =  r'''
            (
                02              # 02: server hello message
                [0-9a-f]{6}     # 3-byte message length
                (030[0-3])      # Agreed version: 0300: SSL 3.0, 0301: TLS 1.0, 
                                #   0302: TLS 1.1, 0303: TLS 1.2
                [0-9a-f]{64}    # 4-byte date followed by 28 random bytes
                ([0-9a-f]{2})   # 1-byte session ID length
	    )
	    '''

        re_part_1 = re_record_layer + re_handshake_layer

	regex = re.compile(re_part_1, re.VERBOSE | re.IGNORECASE)

	match = regex.match(pkt_seq_load)

        if not match:
            return

        groups = match.groups()
        
        # Set whether server hello seen
        handshake_record_group = 0
        server_hello_group = 1
        server_hello_seen = bool(groups[handshake_record_group]) and \
                bool(groups[server_hello_group])
        self._ssl_status.ssl_svr_hello = server_hello_seen 

        ssl_version_group = 2

        # Set SSL version
        if bool(groups[ssl_version_group]):
            ssl_version = groups[ssl_version_group]
            self._ssl_status.ssl_version = ssl_version

        length_session_id_group = 3
        length_session_id = 2 * int(groups[length_session_id_group], 16)

        #print "SERVER HELLO -- ssl_version:", ssl_version, "length_session_id:", length_session_id, \
        #    "groups:", groups

        '''
        With session ID length in hand, we now search the next part of the payload,
        starting with where we left off, and looking for a session ID of the
        specified length, followed by the cipher suite.
        '''

        re_session_id = r'[0-9a-f]{' + re.escape(str(length_session_id)) + r'}'

        # 2-byte code for cipher suite 
        re_cipher_suite = r'([0-9a-f]{4})' 

        # To account for possibility of server hello and change cipher spec   
        # appearing in the same packet or subsequent packets:
        re_any = r'([0-9a-f]*)' 

        re_change_cipher_spec =  r'''
            (
                # RECORD layer:
                14	        # 14: change cipher spec sub-protocol		
                030[0-3]        # 0300: SSL 3.0, 0301: TLS 1.0, 0302: TLS 1.1, 0303: TLS 1.2
                [0-9a-f]{4}     # 2-byte message length
                
                # CHANGE CIPHER SPEC layer:
                01              # 01: change cipher spec message
	    )
	    '''

        re_start_of_encrypted_tunnel =  r'''
            (
                # RECORD layer:
                16	        # 16: handshake sub-protocol		
                030[0-3]        # 0300: SSL 3.0, 0301: TLS 1.0, 0302: TLS 1.1, 0303: TLS 1.2
                [0-9a-f]{4}     # 2-bytes: length of encrypted message to follow
            )
	    '''

        re_full = re_part_1 + re_session_id + re_cipher_suite + re_any + \
                re_change_cipher_spec + re_start_of_encrypted_tunnel

	regex = re.compile(re_full, re.VERBOSE | re.IGNORECASE)
	match = regex.match(pkt_seq_load)

        if not match:
            return


        if match:
            groups = match.groups()

            cipher_suite_group = 4
            cipher = groups[cipher_suite_group] # TODO: IndexError if not
            self._ssl_status.ssl_cipher = cipher

            change_cipher_spec_group = 5
            start_of_encrypted_tunnel_group = 6
            self._ssl_status.ssl_svr_ccs = bool(groups[change_cipher_spec_group]) \
                    and bool(groups[start_of_encrypted_tunnel_group])

            #print "matched_all:", matched_all, "ssl_version:", ssl_version, \
            #    "cipher_suite:", cipher_suite, "groups:", groups,



    def _ssl_handshake_analysis_old(self):
        """Updates SSL_Status object for this packet based on first packets exchanged.
        If TCP handshake is seen then examine the subsequent exchange of messages (sometimes called
        the 'four flights') required to establish the encrypted tunnel, 
        namely Client Hello, Server Hello, plus a Change Cipher Suite from client and server.
        Updates SSL status object with SSL version and cipher
        used. Assumes TCP Fast Open is not used, so Client Hello must be sent 
        in client's third packet.
        """
        ssl_status = self._ssl_status
 
        if not self._tcp_handshake_is_seen():
            ssl_status.ssl_handshake_seen = False
        else:
            try:
                flights = (self._cli_to_svr[2],
                           self._svr_to_cli[2],
                           self._cli_to_svr[3],
                           self._svr_to_cli[3])
            except IndexError:
                print "Not enough packets for SSL handshake"
                ssl_status.ssl_handshake_seen = False
                return

        flight_payloads = [TCP_Payload(flights[i]) for i in range(0,4)]

        # TODO: add try/except block for False case
        if (flight_payloads[0].is_ssl_client_hello()
                and flight_payloads[1].is_ssl_server_hello()
                and flight_payloads[2].is_ssl_client_change_cipher_spec()
                and flight_payloads[3].is_ssl_server_change_cipher_spec()):
            ssl_status.ssl_handshake_seen = True
        else:
            ssl_status.ssl_handshake_seen = False 


    def _ssl_tunnel_analysis(self):
        pass


    def _tcp_close_analysis(self):
        pass


    def _packet_has_payload(self, pkt):
        return len(pkt[TCP].payload) > 0

    def _tcp_handshake_is_seen(self):
        """prereqs: deduplicated, ordered session pair.
        returns two of first packet in cli_to_svr with a TCP payload. 
        """
        session_pair = self
        cli_to_svr = self._cli_to_svr
        svr_to_cli = self._svr_to_cli 

        try:
            if cli_to_svr[0][TCP].flags == 'S' \
                    and svr_to_cli[0][TCP].flags == 'SA' \
                    and cli_to_svr[1][TCP].flags == 'A':
                return True

        except TypeError as e:
            print "_tcp_handshake_is_seen:", e
            return False

        return False

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

if __name__ == '__main__':
    unittest.main()







