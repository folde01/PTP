class Stream_Model:

    def __init__(self, sniffer, stream_reassembler, stream_db):
        self._stream_reassembler = stream_reassembler(sniffer.pcap_filename)
        self._stream_db = stream_db

        # todo: initialise db

    def query_streams()
        stream_collection = self._stream_reassembler.assemble_streams()
        self._stream_db.persist_streams(stream_collection)
        stream_rows = self._stream_db.select_all_streams()
        return stream_rows
