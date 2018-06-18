class Stream_Model:

    def __init__(self, sniffer, stream_reassembler, stream_db, pcap):
        self._stream_reassembler = stream_reassembler
        self._stream_db = stream_db
        self._pcap = pcap

        # todo: pcap handler should be composed of sniffer and timestamper objects.
        # then model is passed a pcap handler which does what ever we need to do with
        # a pcap file before it is handed off to stream_reassembler.

    def query_streams(self):
        db = self._stream_db
        reassembler = self._stream_reassembler
        streams = reassembler.reassemble_streams()
        db.persist_streams(streams)
        streams = db.select_all_streams()
        return streams
