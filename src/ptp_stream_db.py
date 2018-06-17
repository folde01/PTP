from datetime import datetime
import MySQLdb
from ptp_stream import Stream
from ptp_stream_quad import Stream_Quad
import sys
from ptp_logger import Logger


class Stream_DB:

    _logger = Logger(logfile="ptp_stream_db.log")

    def persist_streams(self, stream_collection):
        conn = self._get_conn_to_ptp_db()
	cursor = conn.cursor()
        try:
            for stream in stream_collection: 
                print stream.cli_ip, stream.cli_pt, stream.svr_ip, stream.svr_pt, stream.bytes_to_svr, stream.bytes_to_cli, stream.ts_first_pkt, stream.ts_last_pkt
                sql = """insert into 
                    streams (cli_ip, cli_pt, svr_ip, svr_pt, bytes_to_svr, bytes_to_cli, ts_first_pkt, ts_last_pkt) 
                    values (inet6_aton(\'%s\'), %d, inet6_aton(\'%s\'), %d, %d, %d, '%s', '%s')""" % \
                    (stream.cli_ip, stream.cli_pt, stream.svr_ip, stream.svr_pt,
                     int(stream.bytes_to_svr), int(stream.bytes_to_cli),
                     self._epoch_to_datetime(stream.ts_first_pkt), 
                     self._epoch_to_datetime(stream.ts_last_pkt))
                cursor.execute(sql)
            conn.commit()
        except MySQLdb.OperationalError as e:
            print("Insert failed: ", e)
            conn.rollback()
        finally:
            cursor.close()
            conn.close()

    def _epoch_to_datetime(self, epoch_seconds):
        date = datetime.fromtimestamp(epoch_seconds).strftime('%c')
        return date

    def persist_stream(self, stream):
        conn = self._get_conn_to_ptp_db()
	cursor = conn.cursor()
        try:
            sql = """insert into 
                    streams (cli_ip, cli_pt, svr_ip, svr_pt, bytes_to_svr, 
                    bytes_to_cli, ts_first_pkt, ts_last_pkt) 
                   values (inet6_aton(\'%s\'), %d, inet6_aton(\'%s\'), 
                    %d, %d, %d, '%s', '%s')""" % \
                   (stream.cli_ip, stream.cli_pt, stream.svr_ip, stream.svr_pt, 
                    stream.bytes_to_svr, stream.bytes_to_cli,
                    stream.ts_first_pkt, stream.ts_last_pkt)
            cursor.execute(sql)
            conn.commit()
        except MySQLdb.OperationalError as e:
            print("Insert failed: ", e)
            conn.rollback()
        finally:
            cursor.close()
            conn.close()

    def select_all_streams(self):
        streams = []
        rows = self._select_all_stream_rows()
        for row in rows:
            id, cli_ip, cli_pt, svr_ip, svr_pt, bytes_to_svr, bytes_to_cli, \
                ts_first_pkt, ts_last_pkt = row
            stream = Stream(id=id, cli_ip=cli_ip, cli_pt=cli_pt, svr_ip=svr_ip,
                svr_pt=svr_pt, bytes_to_svr=bytes_to_svr, bytes_to_cli=bytes_to_cli,
                ts_first_pkt=ts_first_pkt, ts_last_pkt=ts_last_pkt)
            streams.append(stream)
        return streams

    def _select_all_stream_rows(self):
        conn = self._get_conn_to_ptp_db()
	cursor = conn.cursor()
	sql =  """select id, inet6_ntoa(cli_ip), cli_pt, inet6_ntoa(svr_ip), svr_pt,
                    bytes_to_svr, bytes_to_cli, ts_first_pkt,
                    ts_last_pkt from streams;"""
	cursor.execute(sql)
	rows = cursor.fetchall()
	cursor.close()
        conn.close()
	return rows

    def select_stream_by_quad_tuple(self, quad_tuple):
        stream = None
        print "quad_tuple:", quad_tuple
        #self.log("select_stream_by_quad_tuple: quad_tuple: " % str(quad_tuple))
        row = self._select_stream_row_by_quad_tuple(quad_tuple)
        print "row:", row
        #self.log("select_stream_by_quad_tuple: row: " % str(row))

        if row:
            id, cli_ip, cli_pt, svr_ip, svr_pt, bytes_to_svr, bytes_to_cli, \
                ts_first_pkt, ts_last_pkt = row
            stream = Stream(id=id, cli_ip=cli_ip, cli_pt=cli_pt, svr_ip=svr_ip,
                svr_pt=svr_pt, bytes_to_svr=bytes_to_svr, bytes_to_cli=bytes_to_cli,
                ts_first_pkt=ts_first_pkt, ts_last_pkt=ts_last_pkt)

        return stream
        
    def _select_stream_row_by_quad_tuple(self, quad_tuple):
        conn = self._get_conn_to_ptp_db()
	cursor = conn.cursor()
	sql =  """select id, inet6_ntoa(cli_ip), cli_pt, inet6_ntoa(svr_ip), svr_pt,
                    bytes_to_svr, bytes_to_cli, ts_first_pkt, ts_last_pkt
                from streams
                where cli_ip = inet6_aton(\'%s\') and cli_pt = %d
                    and svr_ip = inet6_aton(\'%s\')
                    and svr_pt = %d;""" % quad_tuple
	cursor.execute(sql)
	rows = cursor.fetchall()
	cursor.close()
        conn.close()
	return rows[0]

    def update_stream(self, stream):
        conn = self._get_conn_to_ptp_db()
	cursor = conn.cursor()
        try:
            sql =  """update streams 
                    set cli_ip = inet6_aton(\'%s\'), cli_pt = %d, 
                        svr_ip = inet6_aton(\'%s\'), svr_pt = %d,
                        bytes_to_svr = %d, bytes_to_cli = %d,
                        ts_first_pkt = %d, ts_last_pkt = %d
                    where id = %d""" % stream.get_stream_tuple()
            cursor.execute(sql)
            conn.commit()
        except MySQLdb.OperationalError as e:
            print("Update failed: ", e)
            conn.rollback()
        finally:
            cursor.close()
            conn.close()

    def drop_table_streams(self):
        conn = self._get_conn_to_ptp_db()
        cursor = conn.cursor()
        sql = "drop table streams;"
        cursor.execute(sql)
	cursor.close()
        conn.close()

    def _get_conn_to_ptp_db(self):
	conn = MySQLdb.connect(host= "localhost", user="root",
	    passwd="password", db="ptp")
        return conn

    def create_db_ptp(self):
	conn = MySQLdb.connect(host= "localhost", user="root",
	    passwd="password")
        cursor = conn.cursor()
        cursor.execute("create database ptp;")

    def create_table_streams(self):
        conn = self._get_conn_to_ptp_db()
        cursor = conn.cursor()
        #sql = """create table streams (id int not null primary key auto_increment, dest_ip varbinary(16), dest_pt int(5), src_ip varbinary(16), src_pt int(5), b_sent int(6), b_rcvd int(10))"""
        sql = """create table streams (id int not null primary key auto_increment,
            cli_ip varbinary(16),
            cli_pt int(5),
            svr_ip varbinary(16),
            svr_pt int(5), 
            bytes_to_cli int(10),
            bytes_to_svr int(6),
            ts_first_pkt datetime, 
            ts_last_pkt datetime )"""
        cursor.execute(sql)
	cursor.close()
        conn.close()

    def log(self, msg):
        self._logger.log(msg)

