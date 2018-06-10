from ptp_stream import Stream
import nids
from ptp_constants import Constants
import Queue


class Stream_Reassembler:

    def __init__(self, pcap_filename):
        self._pcap_filename = pcap_filename
        self._nids_streams = []
        self._nids_stream_q = Queue.Queue()

    def reassemble_streams(self):
        self._analyse_pcapfile(self._pcap_filename)
        stream_list = self._nids_streams_to_stream_list()
        return stream_list

    def _nids_streams_to_stream_list(self):
        streams = []
        nids_streams = list(self._nids_stream_q.queue)
        for s in nids_streams:
            cli_ip, cli_pt = s.addr[0]
            svr_ip, svr_pt = s.addr[1]
            bytes_to_svr = s.server.count
            bytes_to_cli = s.client.count
            s = Stream(cli_ip=cli_ip, cli_pt=cli_pt, svr_ip=svr_ip,
                    svr_pt=svr_pt, bytes_to_svr=bytes_to_svr, 
                    bytes_to_cli=bytes_to_cli)
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
        stream_quad = self._get_stream_quad(stream)
        print "stream_quad:", stream_quad
        nids_streams = list(self._nids_stream_q.queue)
        for stream_seen in nids_streams:
            stream_quad_seen = self._get_stream_quad(stream_seen)
            if stream_quad == stream_quad_seen:
                print "seen"
                return True
        print "not seen"
        return False

    def _get_stream_quad(self, stream):
        cli_ip, cli_pt = stream.addr[0]
        svr_ip, svr_pt = stream.addr[1]
        return (cli_ip, cli_pt, svr_ip, svr_pt)

    def _get_stream_id(self, stream):
        stream_quad = self._get_stream_quad(stream)
        stream_id = cli_ip + ':' + str(cli_pt) + '-' + svr_ip + ':' + str(svr_pt)
        return stream_id

    def _add_nids_stream(self, stream):
        print "adding to queue:", stream.addr
        self._nids_stream_q.put(stream)

    def _get_nids_streams(self):
        return list(self._nids_stream_q.queue)

    def _callback_gather_stream_objects(self, stream):
        print "-- callback --", stream.addr
        print "BEFORE:", [s.addr for s in self._get_nids_streams()]
        if not self._is_seen_stream(stream):
            print "appending:", stream.addr
            self._add_nids_stream(stream)
        if stream.nids_state == nids.NIDS_JUST_EST:
            stream.client.collect = 1
            stream.server.collect = 1
        else: 
            stream.discard(0)
        print "AFTER:", [s.addr for s in self._get_nids_streams()]

