from scapy.all import rdpcap, PacketList, TCP 

class Stream_Reassembler:

    def __init__(self, pcap_filename):
        self._pcap_filename = pcap_filename
        self._sessions_dict = None 

    def reassemble_streams(self):
	stream_list = self._analyse_pcapfile()
        return stream_list

    def _get_sessions_dict(self):
        if self._sessions_dict == None:
            pkts = rdpcap(self._pcap_filename) 
            self._sessions_dict = pkts.sessions()
        return self._sessions_dict

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

    def _is_TCP_handshake_observed(self, session):

    def _remove_duplicate_packets(self, session):
        pass

    def _remove_corrupt_packets(self, session):
        pass

    def _sort_packets_by_sequence_number(self, session):
        pass

    def _analyse_pcapfile(self):
        # recall scapy session is in one direction
        pass



	



    
