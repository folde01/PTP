class Stream_Model:

    def __init__(self, sniffer, stream_reassembler, stream_db, pcap):
        self._stream_reassembler = stream_reassembler
        self._stream_db = stream_db
        self._pcap = pcap

        # todo: pcap handler should be composed of sniffer and timestamper objects.
        # then model is passed a pcap handler which does what ever we need to do with
        # a pcap file before it is handed off to stream_reassembler.

    def _update_stream_timestamps(self):
        pcap = self._pcap
        quads = pcap.get_quads()
        db = self._stream_db
        
        for quad in quads:
            lo_ts, hi_ts = pcap.lo_and_hi_timestamps(quad)
            stream = db.select_stream_by_quad_tuple(quad) 
            
            if stream:
                stream.ts_first_pkt = lo_ts
                stream.ts_last_pkt = hi_ts
                db.update_stream(stream)

    def query_streams(self):
        db = self._stream_db
        reassembler = self._stream_reassembler
        streams = reassembler.reassemble_streams()
        db.persist_streams(streams)
        self._update_stream_timestamps()
        streams = db.select_all_streams()
        return streams
