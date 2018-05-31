class Stream_Model:

    def __init__(self, sniffer, stream_reassembler, stream_db):
        #self._stream_reassembler = stream_reassembler(sniffer.pcap_filename)
        self._stream_reassembler = stream_reassembler
        self._stream_db = stream_db

        # todo: initialise db

    def query_streams(self):
        streams = self._stream_reassembler.reassemble_streams()
        self._stream_db.persist_streams(streams)
        streams = self._stream_db.select_all_streams()
        return streams
