from scapy.all import rdpcap, PacketList, TCP
from ptp_network import Network
from ptp_constants import Constants
from ptp_connection_status import Stream_Status, TCP_Status, SSL_Status
import unittest
from ptp_session_reassembler import Session_Reassembler
from ptp_tcp_payload import TCP_Payload

class Session_Pair(object):

    def __init__(self, cli_to_svr, svr_to_cli):
        self._cli_to_svr = cli_to_svr
        self._svr_to_cli = svr_to_cli
        self._stream_status = None
        self._tcp_status = None
        self._ssl_status = None

    def get_stream_status(self):
        """
        Returns: 
            A Stream object containing the full analysis of the session pair. This has all the info we need for
        the stream database.
        """
        stream_status = Stream_Status(tcp_status=self._get_tcp_status(), ssl_status=self._get_ssl_status())
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

	tcp_status = TCP_Status(cli_ip=cli_ip, cli_pt=int(cli_pt), svr_ip=svr_ip,
                svr_pt=int(svr_pt), bytes_to_cli=bytes_to_cli,
                bytes_to_svr=bytes_to_svr, ts_first_pkt=float(ts_first_pkt),
                ts_last_pkt=float(ts_last_pkt), ssl_status)

        self._tcp_status = tcp_status
        return tcp_status
 

    def _get_session_payload_size(self, session):
        """returns size of total TCP payload for all packets in bytes"""
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

    def _get_SSL_status(self):
        """Examine use (or otherwise) of SSL protocol.

        Args:
            session_pair: the two TCP sessions representing a bidirectional TCP connection. 
        Returns:
            SSL_Status object containing details of SSL use.
        """
        if self._ssl_status is not None:
            return self._ssl_status

        ssl_handshake_observed = self._ssl_handshake_is_observed()
        ssl_version = self._ssl_()

        self._ssl_status = ssl_status
        return ssl_status

    def _ssl_handshake_is_observed(self):
        """returns whether we saw the TCP handshake followed by the exchange of messages
        required to establish the encrypted tunnel, namely Client hello, Server Hello
        and Change Cipher Suite.
        """
        sp = self 

        if not self._tcp_handshake_is_observed():
            return False

        # Assumes for now that TCP Fast Open is not used, so Client Hello is sent in
        # client's third packet.
        first_flight = TCP_Payload(sp[0][2]).dissect_first_flight()
        second_flight = TCP_Payload(sp[1][2]).dissect_second_flight()
        third_flight = TCP_Payload(sp[0][3]).dissect_third_flight()
        fourth_flight = TCP_Payload(sp[1][3]).dissect_fourth_flight()

        if first_flight.is_ssl_client_hello and \
                second_flight.is_ssl_server_hello and \
                third_flight.is_ssl_client_change_cipher_spec and \
                fourth_flight.is_ssl_server_change_cipher_spec:
            return True
        return False

    def _packet_has_payload(self, pkt):
        return len(pkt[TCP].payload) > 0

    def _tcp_handshake_is_observed(self):
        """prereqs: deduplicated, ordered session pair.
        returns two of first packet in cli_to_svr with a TCP payload. 
        """
        session_pair = self
        cli_to_svr = session_pair[0]
        svr_to_cli = session_pair[1]

        if cli_to_svr[0][TCP].flags == 'S' \
                and svr_to_cli[0][TCP].flags == 'SA' \
                and cli_to_svr[1][TCP].flags == 'A':
            return True
        return False

class Test_Session_Pair(unittest.TestCase):
        
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_tcp_handshake_observed(self):
        pcap = Constants().TEST_PCAP_DIR + '/tcp-handshake-observed.pcap'
        sr = Session_Reassembler(pcap)
        sp = sr.get_session_pairs().values()[0]
        self.assertTrue(sp._tcp_handshake_is_observed())

    def test_tcp_handshake_missing(self):
        pcap = Constants().TEST_PCAP_DIR + '/tcp-handshake-missing.pcap'
        sr = Session_Reassembler(pcap)
        sp = sr.get_session_pairs().values()[0]
        self.assertFalse(sp._tcp_handshake_is_observed())

if __name__ == '__main__':
    unittest.main()







