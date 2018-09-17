from ptp_sniffer import Sniffer
from ptp_session_reassembler import Session_Reassembler
from ptp_session_pair import Session_Pair
from ptp_stream_db import Stream_DB
from ptp_constants import Constants 
import socket


class Analyser(object):

    def __init__(self, existing_pcap_filename=None):
        self._existing_pcap_filename = existing_pcap_filename

        if self._existing_pcap_filename is None:
            self._sniffer = Sniffer()
            pcap_filename = self._sniffer.get_pcap_filename() 
        else:
            pcap_filename = self._existing_pcap_filename

        self._session_reassembler = Session_Reassembler(pcap_filename)
        self._stream_db = Stream_DB()


    def results_no_db(self):
        session_pairs = self._get_session_pairs()
        stream_statuses = [ pair.get_stream_status() for pair in session_pairs ]
        return Stream_Table(stream_statuses) 

    def get_analysis_results(self):
        session_pairs = self._get_session_pairs()
        stream_statuses = [ pair.get_stream_status() for pair in session_pairs ]
	db = self._stream_db
        db.clear_streams()
        db.persist_streams(stream_statuses)
        stream_statuses = db.select_all_streams()
        #print "stream_statuses:", stream_statuses
        #return Stream_Table(stream_statuses) 
        return stream_statuses

    def get_analysis_results2(self):
        session_pairs = self._get_session_pairs()
        stream_statuses = [ pair.get_stream_status() for pair in session_pairs ]
	db = self._stream_db
        db.clear_streams()
        db.persist_streams(stream_statuses)
        stream_statuses = db.select_all_streams() # list of lists (rows)
        results = []
        for ss in stream_statuses:
            svr_ip_addr = ss[1]
            fqdn = self._get_fqdn(svr_ip_addr) 
            result = list(ss)
            result.append(fqdn)
            results.append(result)
        return results 


    def _get_fqdn(self, ip_addr):
        try:
            fqdn = socket.gethostbyaddr(ip_addr)[0]
        except socket.herror:
            fqdn = ip_addr
        return fqdn

    def get_connection_details_row(self, conn_id):
	db = self._stream_db
        row = db.get_connection_details_row(int(conn_id))
        result = list(row)
        svr_ip_addr = result[2] 
        fqdn = self._get_fqdn(svr_ip_addr)
        result.append(fqdn)
        return result 

    def get_encryption_details_row(self, conn_id):
	db = self._stream_db
        return db.get_encryption_details_row(int(conn_id))

    def start_sniffing(self):
        self._sniffer.start()

    def stop_sniffing(self):
        self._sniffer.stop()

    def _get_sniffer(self):
        return self._sniffer
	
    def _get_session_pairs(self):
        return self._session_reassembler.get_session_pairs().values()

    def _get_session_reassembler(self):
        return self._session_reassembler
