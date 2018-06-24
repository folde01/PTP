from scapy.all import rdpcap, PacketList, TCP 
from ptp_network import Network
from ptp_constants import Constants
from ptp_stream import Stream
import unittest
from ptp_session_reassembler import Session_Reassembler


class Stream_Analyser:

    def analyse_session_pair(self, session_pair):
        """Analyses a session pair and returns a stream object"""

        #print "session1:", repr(session_pair[0])
        #print "session2:", repr(session_pair[1])
        cli_to_svr_session = session_pair[0]
        svr_to_cli_session = session_pair[1]

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
        ts_first_pkt, ts_last_pkt = \
            self._get_start_and_end_ts(cli_to_svr_session, svr_to_cli_session)

        using_ssl = \
            self._is_ssl_handshake_complete(cli_to_svr_session, svr_to_cli_session)

        stream = Stream(cli_ip=cli_ip, cli_pt=int(cli_pt), svr_ip=svr_ip, 
                svr_pt=int(svr_pt), bytes_to_cli=bytes_to_cli, 
                bytes_to_svr=bytes_to_svr, ts_first_pkt=float(ts_first_pkt), 
                ts_last_pkt=float(ts_last_pkt)) 

        return stream

    def _get_session_payload_size(self, session):
        """returns size of total TCP payload for all packets in bytes"""
        if session is None:
            return 0
        size = 0
        for pkt in session:
            size += len(pkt[TCP].payload)
        return size 
            
    def _get_start_and_end_ts(self, cli_to_svr_session, svr_to_cli_session):
        """returns two-tuple containing lowest and highest timestamps in Epoch seconds, in microseconds.
        returns None if session is None"""
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

    def _is_ssl_handshake_complete(self, cli_to_svr_session, svr_to_cli_session):
        """returns whether we saw last step of the SSL handshake (on both sides) 
        before the encrypted tunnel is established, namely the Change Cipher Suite
        message"""
        pass

    def _packet_has_payload(self, pkt):
        return len(pkt[TCP].payload) > 0

    def _tcp_handshake_is_observed(self, session_pair):
        """prereqs: deduplicated, ordered session pair.
        returns """
        s0 = session_pair[0]
        s1 = session_pair[1]
        if s0[0][TCP].flags == 'S' and s1[0][TCP].flags == 'SA' and s0[1][TCP].flags == 'A':
            return True
        return False



class TestStreamAnalyser(unittest.TestCase):
	
    def setUp(self):
        pass

    def tearDown(self):
	pass

    def test_tcp_handshake_observed(self):
        pcap = Constants().TEST_PCAP_DIR + '/tcp-handshake-observed.pcap'
        sr = Session_Reassembler(pcap)
        sp = sr.get_session_pairs().values()[0]
        sa = Stream_Analyser() 
        self.assertTrue(sa._tcp_handshake_is_observed(sp))

    def test_tcp_handshake_missing(self):
        pcap = Constants().TEST_PCAP_DIR + '/tcp-handshake-missing.pcap'
        sr = Session_Reassembler(pcap)
        sp = sr.get_session_pairs().values()[0]
        sa = Stream_Analyser() 
        self.assertFalse(sa._tcp_handshake_is_observed(sp))

if __name__ == '__main__':
    unittest.main()
