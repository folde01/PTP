from ptp_stream_table import Stream_Table

class Analyser:

    def __init__(self, sniffer, stream_model, stream_reassembler, stream_db):
        #self._stream_model = stream_model(sniffer, stream_reassembler, stream_db)
        self._stream_model = stream_model

    def results(self):
        streams = self._stream_model.query_streams() 
        table = Stream_Table(streams)
        return table
