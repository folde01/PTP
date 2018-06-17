from scapy.all import rdpcap, PacketList, TCP 
from ptp_network import Network
from ptp_constants import Constants
from ptp_stream import Stream

class Stream_Reassembler:

    def __init__(self, pcap_filename):
        self._pcap_filename = pcap_filename
        self._sessions_dict = None 
        self._session_pairs = None

    def reassemble_streams(self):
	stream_list = self._analyse_pcapfile()
        return stream_list

    def _get_sessions_dict(self):
        if self._sessions_dict == None:
            pkts = rdpcap(self._pcap_filename) 
            self._sessions_dict = pkts.sessions()
        return self._sessions_dict

    def _get_list_of_streams(self):
        """returns a list of Stream objects, based on session pairs"""

        streams = []
        pairs = self._get_session_pairs()

        for pair in pairs:
            quad, sessions = pairs.iteritems()
            cli_ip, cli_pt, svr_ip, svr_pt = quad        
            cli_to_svr_session = sessions[0]
            svr_to_cli_session = sessions[1]
            bytes_to_client = self._get_session_size(cli_to_svr_session)
            bytes_to_svr = self._get_session_size(svr_to_cli_session)
            ts_first_pkt_from_cli, ts_last_pkt_from_cli = self._get_timestamps(cli_to_svr_session)
            ts_first_pkt_from_svr, ts_last_pkt_from_svr = self._get_timestamps(svr_to_cli_session)
            ts_first_pkt = min(ts_first_pkt_from_cli, ts_first_pkt_from_svr)
            ts_last_pkt = max(ts_last_pkt_from_cli, ts_last_pkt_from_svr)

            stream = Stream(cli_ip=cli_ip, cli_pt=cli_pt, svr_ip=svr_ip, 
                    svr_pt=svr_pt, bytes_to_client=bytes_to_client, 
                    bytes_to_svr=bytes_to_svr, ts_first_pkt=ts_first_pkt, 
                    ts_last_pkt=ts_last_pkt) 

            streams.append(stream)

        return streams

    def _get_session_size(self, session):
        """returns size of total TCP payload for all packets in bytes"""
        pass
            
    def _get_timestamps(self, session):
        """returns two-tuple containing lowest and highest timestamps in UNIX epoch seconds"""
        pass

    def _get_session_pairs(self):
        """returns a dict where the key is the 'quad' tuple (cli_ip, cli_pt,
        svr_ip, svr_pt) and the value is a two-tuple of opposing sessions for
        that quad.""" 

        if self._session_pairs is not None:
            return self._session_pairs

        session_pairs = {}
        sessions = self._get_sessions_dict()
        keys = sessions.keys()
        values = sessions.values()
        cli_ip = Network().get_cli_ip()

        for key in keys:
            prot, src, arrow, dst = key.split()
            src_ip, src_pt = src.split(':') 
            dst_ip, dst_pt = dst.split(':') 

            if src_ip != cli_ip or dst_ip == Constants().KILL_PKT_IP: 
                continue

            opp_key = "%s %s:%s %s %s:%s" % \
                (prot, dst_ip, str(dst_pt), arrow, src_ip, str(src_pt))  
            session = sessions[key]
            quad = (src_ip, src_pt, dst_ip, dst_pt)

            if opp_key in keys:
                opp_session = sessions[opp_key]
            else:
                print "%s is client-to-server only" % str(quad)
                opp_session = None

            session_pairs[quad] = (session, opp_session)

        self._session_pairs = session_pairs
        return self._session_pairs

    def _print_sessions_dict_summary(self):
        for k,v in self._get_sessions_dict().iteritems():
            print k, "\n", v,"\n"

    def _print_session_summary(self, session):
        for pkt in session:
            print repr(pkt), "\n" 

    def _get_session_by_quad_tuple(self, quad):
        result = None
        src_ip, src_pt, dst_ip, dst_pt = quad
        key_to_check = 'TCP %s:%s > %s:%s' % (src_ip, src_pt, dst_ip, dst_pt)
        sessions = self._get_sessions_dict()
        for key, session in sessions.iteritems(): 
            if key == key_to_check:
                result = session
                break
        return result

    def _packet_has_payload(self, pkt):
        return len(pkt[TCP].payload) > 0

    def _remove_corrupt_packets(self, session):
        '''Compare the provided checksum with a generated one. We can generate
        one by deleting the checksum and then rebuilding the packet based on its
        string representation. This may return an out-of-order result but 
        we'll order elsewhere.
        Credit to Almog Cohen - https://stackoverflow.com/a/11648093'''

        for pkt in session:
            chksum = pkt[TCP].chksum
            del pkt[TCP].chksum
            new_pkt = pkt.__class__(str(pkt))
            session.remove(pkt)
            comparison = "chksum: %s, new_chksum: %s" % (str(chksum), str(new_pkt[TCP].chksum))
            print repr(pkt), "\n", comparison, "\n"
            if chksum == new_pkt[TCP].chksum:
                session.append(new_pkt)
            else:
                print "chksum changed\n"


    def _TCP_handshake_is_observed(self, session):
        pass


    def _remove_duplicate_packets(self, session):
        '''This is required based on the TCP protocol. This method only covers cases where packets  
        being compared have the same sequence numbers and have payloads. There may be other cases,
        e.g. duplicate acknowledgements, but these need to be identified in the context of the
        other side's session. We may need to care about those cases, e.g. because we need to know
        whether and when the TCP-handshake completes, as that seems to determine whether/when 
        we should start looking for the SSL handshake. This may return an out-of-order result but
        we'll order elsewhere.'''

        unique_loaded_pkts = [] 
        other_pkts = []

        def seq_seen(pkt):
            for p in unique_loaded_pkts:
                if pkt[TCP].seq == p[TCP].seq:
                    return True
            return False

        for pkt in session:
            if self._packet_has_payload(pkt):
                if not seq_seen(pkt):
                    unique_loaded_pkts.append(pkt)
            else:
                other_pkts.append(pkt)
        
        return PacketList(unique_loaded_pkts + other_pkts)

    def _sort_packets_by_sequence_number(self, session):
        pass

    def _analyse_pcapfile(self):
        # recall scapy session is in one direction
        pass
