from ptp_sniffer import Sniffer
from ptp_session_reassembler import Session_Reassembler
from ptp_stream_analyser import Stream_Analyser
from ptp_stream_db import Stream_DB
from ptp_stream_table import Stream_Table
from ptp_constants import Constants 


class Analyser:

    def __init__(self):
	self._sniffer = Sniffer()
	self._session_reassembler = \
            Session_Reassembler(self._sniffer.get_pcap_filename())
	self._stream_analyser = Stream_Analyser()
	self._stream_db = Stream_DB()

    def results(self):
        session_pairs = self._get_session_pairs()
        analyse = self._stream_analyser.analyse_session_pair
        streams = [ analyse(pair) for pair in session_pairs ]
	db = self._stream_db
        db.clear_streams()
        db.persist_streams(streams)
        return Stream_Table(db.select_all_streams()) 

    def get_sniffer(self):
        return self._sniffer
	
    def _get_session_pairs(self):
        return self._session_reassembler.get_session_pairs().values()

    def _get_session_reassembler(self):
        return self._session_reassembler
