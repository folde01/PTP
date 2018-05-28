import nids

class Stream_Reassembler:

    def __init__(self, pcap_filename):
        self._pcap_filename = pcap_filename
        self._nids_streams = []

    def reassemble_streams(self):
        self._analyse_pcapfile(self._pcap_filename)
        stream_tuples = self._nids_streams_to_tuples()
        return stream_tuples 

    def _nids_streams_to_tuples(self):
        tuples = []
        for s in self._nids_streams:
            cli_ip, cli_pt = s.addr[0]
            svr_ip, svr_pt = s.addr[1]
            bytes_to_svr = s.server.count
            bytes_to_cli = s.client.count
            t = (cli_ip, cli_pt, svr_ip, svr_pt, bytes_to_svr, bytes_to_cli)
            tuples.append(t)
        return tuples

    def _analyse_pcapfile(self, pcap_filename):
        nids.param("scan_num_hosts", 0) # disable portscan detection
        nids.chksum_ctl([('0.0.0.0/0', False)]) # disable checksumming
        nids.param("filename", pcap_filename)
        nids.init()
        nids.register_tcp(self._callback_gather_stream_objects)
        nids.run()

    def _callback_gather_stream_objects(self, stream):
        if stream not in self._nids_streams:
            self._nids_streams.append(stream)
        if stream.nids_state == nids.NIDS_JUST_EST:
            stream.client.collect = 1
            stream.server.collect = 1
        else: 
            stream.discard(0)
