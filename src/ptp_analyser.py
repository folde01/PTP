class Analyser:

    def __init__(self, sniffer, stream_model, stream_reassembler, stream_db):
        self._stream_model = stream_model(sniffer, stream_reassembler, stream_db)) 

    def results(self):
        stream_rows = self._stream_model.query_streams() 
        return stream_rows
