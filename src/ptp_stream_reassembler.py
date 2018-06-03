from ptp_stream import Stream
import nids

class Stream_Reassembler:

    def __init__(self, pcap_filename):
        self._pcap_filename = pcap_filename
        self._nids_streams = []

    def reassemble_streams(self):
        self._analyse_pcapfile(self._pcap_filename)
        stream_list = self._nids_streams_to_stream_list()
        return stream_list

    def _nids_streams_to_stream_list(self):
        streams = []
        for s in self._nids_streams:
            cli_ip, cli_pt = s.addr[0]
            svr_ip, svr_pt = s.addr[1]
            bytes_to_svr = s.server.count
            bytes_to_cli = s.client.count
            ts_first_pkt = 0
            ts_last_pkt = 0
            s = Stream(cli_ip, cli_pt, svr_ip, svr_pt, bytes_to_svr, bytes_to_cli,
                    ts_first_pkt, ts_last_pkt)
            streams.append(s)
        return streams

    def _analyse_pcapfile(self, pcap_filename):
        nids.param("scan_num_hosts", 0) # disable portscan detection
        nids.chksum_ctl([('0.0.0.0/0', False)]) # disable checksumming
        nids.param("filename", pcap_filename)
        nids.init()
        nids.register_tcp(self._callback_gather_stream_objects)
        nids.run()

    def _is_seen_stream(self, stream):
        cli_ip, cli_pt = stream.addr[0]
        svr_ip, svr_pt = stream.addr[1]
        for stream_seen in self._nids_streams:
            cli_ip_seen, cli_pt_seen = stream_seen.addr[0]
            svr_ip_seen, svr_pt_seen = stream_seen.addr[1]
            if (cli_ip, cli_pt, svr_ip, svr_pt) == (cli_ip_seen, cli_pt_seen, svr_ip_seen, svr_pt_seen):
                return True
        return False

    def _callback_gather_stream_objects(self, stream):
        if not self._is_seen_stream(stream):
            self._nids_streams.append(stream)
        if stream.nids_state == nids.NIDS_JUST_EST:
            stream.client.collect = 1
            stream.server.collect = 1
        else: 
            stream.discard(0)
