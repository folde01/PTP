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

    def _packet_has_payload(self, pkt):
        return len(pkt[TCP].payload) > 0

    def _packet_has_valid_checksum(self, pkt):
        '''Compare the provided checksum with a generated one. We can generate
        one by deleting the checksum and then rebuilding the packet based on its
        string representation.
        Credit to Almog Cohen - https://stackoverflow.com/a/11648093'''

        chksum = pkt[TCP].chksum
        del pkt[TCP].chksum
        pkt = pkt.__class__(str(pkt))
        return chksum == pkt[TCP].chksum

    def _TCP_handshake_is_observed(self, session):
        pass


    def _remove_duplicate_packets(self, session):
        '''This is required based on the TCP protocol. This method only covers cases where packets  
        being compared have the same sequence numbers and have payloads. There may be other cases,
        e.g. duplicate acknowledgements, but these need to be identified in the context of the
        other side's session. We may need to care about those cases, e.g. because we need to know
        whether and when the TCP-handshake completes, as that seems to determine whether/when 
        we should start looking for the SSL handshake.'''

        unique_pkts = [] 

        for pkt1 in session:
            if self._packet_has_payload(pkt):
                seq1 = pkt1[TCP].seq
                for pkt2 in session: 
                    if pkt2 is not pkt1: 
                        seq2 = pkt2[TCP].seq
                        if seq1 == seq2:
                            break
            else: 
                unique_pkts.append(pkt)

        return unique_pkts

    def _remove_corrupt_packets(self, session):
        pass

    def _sort_packets_by_sequence_number(self, session):
        pass

    def _analyse_pcapfile(self):
        # recall scapy session is in one direction
        pass
