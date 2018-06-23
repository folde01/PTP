from scapy.all import rdpcap, PacketList, TCP 
import hashlib
from ptp_network import Network
from ptp_constants import Constants

class Session_Reassembler:

    def __init__(self, pcap_filename):
        self._pcap_filename = pcap_filename
        self._sessions_dict = None 
        self._session_pairs = None

    def get_session_pairs(self):
        """returns a dict where the key is the 'quad' tuple (cli_ip, cli_pt,
        svr_ip, svr_pt) and the value is a two-tuple of opposing sessions for
        that quad.""" 

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

    def _get_sessions_dict(self):
        pkts = rdpcap(self._pcap_filename) 
        sessions = pkts.sessions()

        for session in sessions.values():
            self._remove_duplicate_packets(session)
            self._sort_session_by_seq_no(session)

        self._sessions_dict = sessions
        return self._sessions_dict 

    def _sort_session_by_seq_no(self, session):
        """Sorts packets of session in-place by TCP sequence number, as packets are
        sometimes sniffed out of sequence number order. We need them in that order to 
        see e.g. TCP and SSL handshake completions."""
        def get_seq(pkt):
            return pkt[TCP].seq
        session.sort(key=get_seq)


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
        To make it easier to read, make a few reusable, function-like methods 
        first and use them to build up to the bigger algorithm.
        '''

        def payload_len(pkt): return len(pkt[TCP].payload)
        def flags(pkt): return str(pkt[TCP].flags)
        def seq(pkt): return pkt[TCP].seq
        def ack(pkt): return pkt[TCP].ack
        def chksum(pkt): return pkt[TCP].chksum
        def md5(*args):
            str_args = map(str, args)
            return hashlib.md5("".join(str_args)).hexdigest()
        def is_ack(pkt):
            return flags(pkt) == 'A' and payload_len(pkt) == 0
        def hash_ack(pkt): return md5(seq(pkt)), ack(pkt) 
        def is_data(pkt):
            return payload_len(pkt) != 0 and (flags(pkt) == 'A' or flags(pkt) == 'PA')
        def hash_data(pkt): return md5(seq(pkt), ack(pkt), chksum(pkt)) 
        def is_syn(pkt):
            return flags(pkt) == 'S' and ack(pkt) == 0
        def hash_syn(pkt): return md5(seq(pkt)) 
        def is_synack(pkt): return flags(pkt) == 'SA'
        def hash_synack(pkt): return md5(seq(pkt), ack(pkt)) 

        ack_pkts = {}
        data_pkts = {}
        syn_pkts = {}
        synack_pkts = {}

        deduped = [] 

        # if it's one of our cases and we haven't seen it then add to appropriate hash table and deduped.
        # if not one of our cases, just add it to deduped.
        for pkt in session:
            if is_ack(pkt):
                #print "ACK"
                if (hash_ack(pkt) not in ack_pkts):
                    #print "ACK not seen"
                    deduped.append(pkt)
                    ack_pkts[hash_ack(pkt)] = pkt

            elif is_data(pkt):
                #print "DATA"
                if (hash_data(pkt) not in data_pkts):
                    #print "DATA not seen"
                    deduped.append(pkt)
                    data_pkts[hash_data(pkt)] = pkt

            elif is_syn(pkt):
                #print "SYN"
                if (hash_syn(pkt) not in syn_pkts):
                    #print "SYN not seen"
                    deduped.append(pkt)
                    syn_pkts[hash_syn(pkt)] = pkt

            elif is_synack(pkt):
                #print "SYNACK"
                if (hash_synack(pkt) not in synack_pkts):
                    #print "SYNACK not seen"
                    deduped.append(pkt)
                    synack_pkts[hash_synack(pkt)] = pkt

            else:
                #print "NO CASE"
                deduped.append(pkt)
                
        for pkt in session:
            if pkt not in deduped:
                session.remove(pkt)

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
