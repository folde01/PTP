from scapy.all import rdpcap, PacketList, TCP 
from ptp_network import Network
from ptp_constants import Constants
from ptp_stream import Stream
import os
import hashlib

class Stream_Reassembler:

    def __init__(self, pcap_filename):
        self._pcap_filename = pcap_filename
        self._sessions_dict = None 
        self._session_pairs = None

    def reassemble_streams(self):
	stream_list = self._get_list_of_streams()
        self._reinitialise()
        return stream_list

    def _reinitialise(self):
        self._sessions_dict = None
        self._session_pairs = None
        #try:
            #os.remove(self._pcap_filename)
        #except OSError, e:
            #print "Error deleting pcap file %s: %s" % (e.filename, e.strerror)

    def _get_sessions_dict(self):
        if self._sessions_dict == None:
            pkts = rdpcap(self._pcap_filename) 
            self._sessions_dict = pkts.sessions()
        return self._sessions_dict

    def _get_list_of_streams(self):
        """returns a list of Stream objects, based on session pairs"""
        streams = []
        pairs = self._get_session_pairs()

        for quad, sessions in pairs.iteritems():
            cli_ip, cli_pt, svr_ip, svr_pt = quad        
            cli_to_svr_session = sessions[0]
            svr_to_cli_session = sessions[1]
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

            streams.append(stream)

        return streams


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

    def _sort_session_by_seq_no(self, session):
        """Sorts packets of session in-place by TCP sequence number, as packets are
        sometimes sniffed out of sequence number order. We need them in that order to 
        see e.g. TCP and SSL handshake completions."""
        def get_seq(pkt):
            return pkt[TCP].seq
        session.sort(key=get_seq)

        
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
            # e.g. key = 'TCP 151.101.16.175:443 > 192.168.1.12:44071'
            #  opp_key = 'TCP 192.168.1.12:44071 > 151.101.16.175:443'
            prot, src, arrow, dst = key.split()
            src_ip, src_pt = src.split(':') 
            dst_ip, dst_pt = dst.split(':') 

            if dst_ip == Constants().KILL_PKT_IP: 
                continue

            opp_key = "%s %s:%s %s %s:%s" % \
                (prot, dst_ip, str(dst_pt), arrow, src_ip, str(src_pt))  
            session = sessions[key]

            if src_ip == cli_ip:
                quad = (src_ip, src_pt, dst_ip, dst_pt)
                if quad in session_pairs.keys(): 
                    # we must've hit opp_key earlier 
                    continue
                if opp_key in keys:
                    #print "%s is both directions" % str(quad)
                    opp_session = sessions[opp_key]
                else:
                    #print "%s is client-to-server only" % str(quad)
                    opp_session = None
                session_pairs[quad] = (session, opp_session)
            else:
                quad = (dst_ip, dst_pt, src_ip, src_pt)
                if quad in session_pairs.keys(): 
                    # we must've hit opp_key earlier 
                    continue
                if opp_key in keys:
                    #print "%s is both directions" % str(quad)
                    opp_session = sessions[opp_key]
                else:
                    #print "%s is server-to-client only" % str(quad)
                    opp_session = None
                session_pairs[quad] = (opp_session, session)

        self._session_pairs = session_pairs
        return self._session_pairs

    def _get_opposing_session_key(self, key):
        prot, src, arrow, dst = key.split()
        src_ip, src_pt = src.split(':') 
        dst_ip, dst_pt = dst.split(':') 
        opp_key = "%s %s:%s %s %s:%s" % \
            (prot, dst_ip, str(dst_pt), arrow, src_ip, str(src_pt))  
        return opp_key
        

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


    def _TCP_handshake_is_observed(self, session_pair):
        """prereqs: deduplicated, ordered session pair"""
        pass

    def _remove_duplicate_packets(self, session):
        '''Packets are considered duplicate if they fall under one of these cases:
        both directions:
        * duplicate ack: no payload, flags=A, same seq and ack numbers.
        * duplicate data: flags=PA or A, same seq/ack/TCP chksum, same non-zero payload
        cli_to_svr:
        * duplicate syn: flags=S, same seq numbers 
        svr_to_cli:
        * duplicate synack: flags=SA, same seq/ack
        todo:
        * duplicate fin: 
        * duplicate finack:
        
        We hash the packets (credit: https://stackoverflow.com/a/3350656) depending on
        context. We'll need to make separate hash tables for each case to check.
        '''

        def payload_len(pkt):
            return len(pkt[TCP].payload)

        def flags(pkt):
            return str(pkt[TCP].flags)

        def seq(pkt):
            return pkt[TCP].seq

        def ack(pkt):
            return pkt[TCP].ack

        def chksum(pkt):
            return pkt[TCP].chksum

        def md5(*args):
            return hashlib.md5("".join(args)).hexdigest()

        def is_ack(pkt):
            return flags(pkt) == 'A' and payload_len(pkt) = 0

        def hash_ack(pkt):
            return md5(seq(pkt), ack(pkt) 

        def is_data(pkt):
            return payload_len(pkt) != 0 and (flags(pkt) == 'A' or flags(pkt) == 'PA')

        def hash_data(pkt):
            return md5(seq(pkt), ack(pkt), chksum(pkt)) 

        def is_syn(pkt):
            return flags(pkt) == 'S' and ack(pkt) == 0

        def hash_syn(pkt):
            return md5(seq(pkt)) 
        
        def is_synack(pkt):
            return flags(pkt) == 'SA'

        def hash_synack(pkt):
            return md5(seq(pkt), ack(pkt)) 

        ack_pkts = {}
        data_pkts = {}
        syn_pkts = {}
        synack_pkts = {}

        # build our hash tables
        for pkt in session:
            if is_ack(pkt):
                ack_pkts[hash_ack(pkt)] = pkt

            elif is_data(pkt):
                data_pkts[hash_data(pkt)] = pkt

            elif is_syn(pkt):
                syn_pkts[hash_syn(pkt)] = pkt
                
            elif is_synack(pkt):
                synack_pkts[hash_synack(pkt)] = pkt

        deduped_pkt_list = [] 

        # add pkt to results if not already in a hash table 
        for pkt in session:
            if is_ack(pkt) and (hash_ack(pkt) not in ack_pkts):
                    deduped_pkt_list.append(pkt)

            elif is_data(pkt) and (hash_data(pkt) not in data_pkts):
                    deduped_pkt_list.append(pkt)

            elif is_syn(pkt) and (hash_syn(pkt) not in syn_pkts):
                    deduped_pkt_list.append(pkt)

            else is_synack(pkt) and (hash_synack(pkt) not in synack_pkts):
                    deduped_pkt_list.append(pkt)
                
        return PacketList(deduped_pkt_list)
