import MySQLdb
from ptp_stream import Stream

class Stream_DB:

    def persist_streams(self, stream_collection):
        conn = self._get_conn_to_ptp_db()
	cursor = conn.cursor()
        try:
            for stream in stream_collection: 
                sql = """insert into 
                    streams (cli_ip, cli_pt, svr_ip, svr_pt, bytes_to_svr, bytes_to_cli) 
                    values (inet6_aton(%s), %d, inet6_aton(%s), %d, %d, %d)""", (stream.cli_ip, stream.cli_pt, stream.svr_ip, stream.svr_pt, stream.bytes_to_svr, stream.bytes_to_cli)
                cursor.execute(sql)
            conn.commit()
        except:
            conn.rollback()
	cursor.close()
        conn.close()

    def persist_stream(self, stream):
        conn = self._get_conn_to_ptp_db()
	cursor = conn.cursor()
        sql = """insert into 
                 streams (cli_ip, cli_pt, svr_ip, svr_pt, 
                    bytes_to_svr, bytes_to_cli) 
                values (inet6_aton(%s), %d, inet6_aton(%s), %d, %d, %d)""" % (stream.cli_ip, stream.cli_pt, stream.svr_ip, stream.svr_pt, stream.bytes_to_svr, stream.bytes_to_cli)
        cursor.execute(sql)
        conn.commit()
	cursor.close()
        conn.close()

    def persist_stream_0(self, stream):
        conn = self._get_conn_to_ptp_db()
	cursor = conn.cursor()
        try:
            sql = """insert into 
                     streams (cli_ip, cli_pt, svr_ip, svr_pt, 
                        bytes_to_svr, bytes_to_cli) 
                    values (inet6_aton(%s), %d, inet6_aton(%s), %d, %d, %d)""", (stream.cli_ip, stream.cli_pt, stream.svr_ip, stream.svr_pt, stream.bytes_to_svr, stream.bytes_to_cli)
            cursor.execute(sql)
            conn.commit()
        except:
            conn.rollback()
	cursor.close()
        conn.close()

    def persist_streams_old(self, stream_collection):
        conn = self._get_conn_to_ptp_db()
	cursor = conn.cursor()
        try:
            for stream_tuple in stream_collection: 
                sql = """insert into 
                    streams (cli_ip, cli_pt, svr_ip, svr_pt, bytes_to_svr, bytes_to_cli) 
                    values (inet6_aton(%s), %d, inet6_aton(%s), %d, %d, %d)""", stream_tuple
                cursor.execute(sql)
            conn.commit()
        except:
            conn.rollback()
	cursor.close()
        conn.close()

    def select_all_streams(self):
        conn = self._get_conn_to_ptp_db()
	cursor = conn.cursor()
	sql =  """select * from streams;"""
	cursor.execute(sql)
	rows = cursor.fetchall()
	cursor.close()
        conn.close()
	return rows

    def _create_table_streams(self):
        conn = self._get_conn_to_ptp_db()
        cursor = conn.cursor()
        #sql = """create table streams (id int not null primary key auto_increment, dest_ip varbinary(16), dest_pt int(5), src_ip varbinary(16), src_pt int(5), b_sent int(6), b_rcvd int(10))"""
        sql = """create table streams (id int not null primary key auto_increment,
            cli_ip varbinary(16),
            cli_pt int(5),
            svr_ip varbinary(16),
            svr_pt int(5), 
            bytes_to_client int(10),
            bytes_to_svr int(6))"""
        cursor.execute(sql)
	cursor.close()
        conn.close()


    def _get_conn_to_ptp_db(self):
	conn = MySQLdb.connect(host= "localhost", user="root",
	    passwd="password", db="ptp")
        return conn

