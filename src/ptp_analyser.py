from ptp_sniffer import Sniffer
from ptp_session_reassembler import Session_Reassembler
from ptp_session_pair import Session_Pair
from ptp_stream_db import Stream_DB
from ptp_constants import Constants 


class Analyser:

    def __init__(self):
	self._sniffer = Sniffer()
	self._session_reassembler = \
            Session_Reassembler(self._sniffer.get_pcap_filename())
	self._stream_db = Stream_DB()

    def results_no_db(self):
        session_pairs = self._get_session_pairs()
        stream_statuses = [ pair.get_stream_status() for pair in session_pairs ]
        return Stream_Table(stream_statuses) 

    def results(self):
        session_pairs = self._get_session_pairs()
        stream_statuses = [ pair.get_stream_status() for pair in session_pairs ]
	db = self._stream_db
        db.clear_streams()
        db.persist_streams(stream_statuses)
        stream_statuses = db.select_all_streams()
        #print "stream_statuses:", stream_statuses
        #return Stream_Table(stream_statuses) 
        return stream_statuses

    def get_sniffer(self):
        return self._sniffer
	
    def _get_session_pairs(self):
        return self._session_reassembler.get_session_pairs().values()

    def _get_session_reassembler(self):
        return self._session_reassembler
