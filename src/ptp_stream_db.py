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
                    values (inet6_aton(\'%s\'), %d, inet6_aton(\'%s\'), %d, %d, %d)""" % \
                    (stream.cli_ip, stream.cli_pt, stream.svr_ip, stream.svr_pt,
                     stream.bytes_to_svr, stream.bytes_to_cli)
                cursor.execute(sql)
            conn.commit()
        except:
            conn.rollback()
        finally:
            cursor.close()
            conn.close()

    def persist_stream(self, stream):
        conn = self._get_conn_to_ptp_db()
	cursor = conn.cursor()
        try:
            sql = """insert into 
                     streams (cli_ip, cli_pt, svr_ip, svr_pt, bytes_to_svr, bytes_to_cli) 
                    values (inet6_aton(\'%s\'), %d, inet6_aton(\'%s\'), %d, %d, %d)""" % \
                    (stream.cli_ip, stream.cli_pt, stream.svr_ip, stream.svr_pt, 
                     stream.bytes_to_svr, stream.bytes_to_cli)
            cursor.execute(sql)
            conn.commit()
        except:
            conn.rollback()
        finally:
            cursor.close()
            conn.close()

    def select_all_streams(self):
        streams = []
        rows = self._select_all_stream_rows()
        for row in rows:
            stream = Stream(cli_ip = row[0], 
                    cli_pt = row[1], svr_ip = row[2], svr_pt = row[3],
                    bytes_to_svr = row[4], bytes_to_cli = row[5])
            streams.append(stream)
        return streams

    def _select_all_stream_rows(self):
        conn = self._get_conn_to_ptp_db()
	cursor = conn.cursor()
        # todo: don't use distinct
	sql =  "select distinct inet6_ntoa(cli_ip), cli_pt, inet6_ntoa(svr_ip), svr_pt, bytes_to_svr, bytes_to_cli from streams;"
	cursor.execute(sql)
	rows = cursor.fetchall()
	cursor.close()
        conn.close()
	return rows

    def _drop_table_streams(self):
        conn = self._get_conn_to_ptp_db()
        cursor = conn.cursor()
        sql = "drop table streams;"
        cursor.execute(sql)
	cursor.close()
        conn.close()

    def _create_table_streams(self):
        conn = self._get_conn_to_ptp_db()
        cursor = conn.cursor()
        #sql = """create table streams (id int not null primary key auto_increment, dest_ip varbinary(16), dest_pt int(5), src_ip varbinary(16), src_pt int(5), b_sent int(6), b_rcvd int(10))"""
        sql = """create table streams (id int not null primary key auto_increment,
            cli_ip varbinary(16),
            cli_pt int(5),
            svr_ip varbinary(16),
            svr_pt int(5), 
            bytes_to_cli int(10),
            bytes_to_svr int(6))"""
        cursor.execute(sql)
	cursor.close()
        conn.close()


    def _get_conn_to_ptp_db(self):
	conn = MySQLdb.connect(host= "localhost", user="root",
	    passwd="password", db="ptp")
        return conn
