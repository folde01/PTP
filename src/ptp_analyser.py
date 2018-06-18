from ptp_stream_table import Stream_Table

class Analyser:

    def __init__(self, stream_model):
        self._stream_model = stream_model

    def results(self):
        streams = self._stream_model.get_all_streams() 
        table = Stream_Table(streams)
        return table
