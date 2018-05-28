class Stream_Model:

    def __init__(self, sniffer, stream_reassembler, stream_db):
        self._stream_reassembler = stream_reassembler(sniffer.pcap_filename)
        self._stream_db = stream_db()

        # todo: initialise db

    def query_streams()
        stream_collection = self._stream_reassembler.assemble_streams()
        self._persist_streams(stream_collection)
        stream_rows = self._select_all_streams()
        return stream_rows



    def _persist_streams(self, stream_collection):
        conn = _get_conn_to_ptp_db()
	cursor = conn.cursor()
        try:
            for stream_tuple in stream_collection: 
                sql = """insert into 
                    streams (cli_ip, cli_pt, svr_ip, svr_pt, bytes_to_svr, bytes_to_cli) 
                    values (inet6_aton(%s), %d, inet6_aton(%s), %d, %d, %d)""", stream_tuple)
                cursor.execute(sql)
            conn.commit()
        except:
            conn.rollback()
	cursor.close()

    def _select_all_streams(self):
        conn = _get_conn_to_ptp_db()
	cursor = conn.cursor()
	sql =  """select * from streams;"""
	cursor.execute(sql)
	rows = cursor.fetchall()
	cursor.close()
	return rows

    def _get_conn_to_ptp_db(self):
	return MySQLdb.connect(host= "localhost", user="root",
	    passwd="password", db="ptp")
