from datetime import datetime
import time
import MySQLdb
from ptp_connection_status import Stream_Status, TCP_Status, SSL_Status
import sys
from ptp_logger import Logger


class Stream_DB:

    _logger = Logger(logfile="ptp_stream_db.log")

    _sql_streams_table_columns = """streams (cli_ip, cli_pt, svr_ip, svr_pt, bytes_to_svr, bytes_to_cli, ts_first_pkt, ts_last_pkt, ssl_cli_hello, ssl_cli_ccs, ssl_svr_hello, ssl_version, ssl_cipher, ssl_svr_ccs)"""

    _sql_stream_table_values = """VALUES (inet6_aton(\'%s\'), %d, inet6_aton(\'%s\'), %d, %d, %d, '%s', '%s', %d, %d, %d, '%s', '%s', %d)"""

    def select_all_streams(self):
        streams = []
        rows = self._select_all_stream_rows()
        for row in rows:
            id, cli_ip, cli_pt, svr_ip, svr_pt, bytes_to_svr, bytes_to_cli, \
                ts_first_pkt, ts_last_pkt, ssl_cli_hello, ssl_cli_ccs, \
                ssl_svr_hello, ssl_version, ssl_cipher, ssl_svr_ccs = row
            tcp_status = TCP_Status(cli_ip=cli_ip, cli_pt=cli_pt, svr_ip=svr_ip,
                svr_pt=svr_pt, bytes_to_svr=bytes_to_svr, bytes_to_cli=bytes_to_cli,
                ts_first_pkt=ts_first_pkt, ts_last_pkt=ts_last_pkt)
            ssl_status = SSL_Status(ssl_cli_hello=bool(ssl_cli_hello), ssl_cli_ccs=bool(ssl_cli_ccs), \
                    ssl_svr_hello=bool(ssl_svr_hello), ssl_version=ssl_version, \
                    ssl_cipher=ssl_cipher, ssl_svr_ccs=bool(ssl_svr_ccs))
            stream_status = Stream_Status(id=id, tcp_status=tcp_status, \
                    ssl_status=ssl_status).get_flattened()
            streams.append(stream_status)
        return streams

    def persist_streams(self, stream_statuses):
        conn = self._get_conn_to_ptp_db()
	cursor = conn.cursor()
        try:
            for stream_status in stream_statuses: 
                ts = stream_status.tcp_status
                ss = stream_status.ssl_status
                #print ts.cli_ip, ts.cli_pt, ts.svr_ip, ts.svr_pt, ts.bytes_to_svr, ts.bytes_to_cli, ts.ts_first_pkt, ts.ts_last_pkt

                sql = ' '.join("INSERT INTO", _sql_streams_table_columns, _sql_stream_table_values) % \
                    (ts.cli_ip, ts.cli_pt, ts.svr_ip, ts.svr_pt, int(ts.bytes_to_svr), int(ts.bytes_to_cli),
                     self._epoch_to_datetime(ts.ts_first_pkt), self._epoch_to_datetime(ts.ts_last_pkt),
                     ss.client_hello, ss.client_change_cipher_spec, ss.server_hello, ss.version, 
                     ss.cipher, ss.server_change_cipher_spec)
 
                cursor.execute(sql)
            conn.commit()
        except MySQLdb.OperationalError as e:
            print("Insert failed: ", e)
            conn.rollback()
        finally:
            cursor.close()
            conn.close()

    def persist_streams_old(self, stream_statuses):
        conn = self._get_conn_to_ptp_db()
	cursor = conn.cursor()
        try:
            for stream_status in stream_statuses: 
                tcp_status = stream_status.tcp_status
                ssl_status = stream_status.ssl_status
                #print tcp_status.cli_ip, tcp_status.cli_pt, tcp_status.svr_ip, tcp_status.svr_pt, tcp_status.bytes_to_svr, tcp_status.bytes_to_cli, tcp_status.ts_first_pkt, tcp_status.ts_last_pkt
                sql = """insert into 
                    streams (cli_ip, cli_pt, svr_ip, svr_pt, bytes_to_svr, bytes_to_cli, ts_first_pkt, ts_last_pkt) 
                    values (inet6_aton(\'%s\'), %d, inet6_aton(\'%s\'), %d, %d, %d, '%s', '%s')""" % \
                    (tcp_status.cli_ip, tcp_status.cli_pt, tcp_status.svr_ip, tcp_status.svr_pt,
                     int(tcp_status.bytes_to_svr), int(tcp_status.bytes_to_cli),
                     self._epoch_to_datetime(tcp_status.ts_first_pkt), 
                     self._epoch_to_datetime(tcp_status.ts_last_pkt))
                cursor.execute(sql)
            conn.commit()
        except MySQLdb.OperationalError as e:
            print("Insert failed: ", e)
            conn.rollback()
        finally:
            cursor.close()
            conn.close()

    def _epoch_to_datetime(self, epoch_seconds):
        #date = datetime.fromtimestamp(epoch_seconds).strftime('%c')
        date = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(epoch_seconds))
        return date

    def persist_stream(self, stream_status):
        ts = stream_status.tcp_status
        ss = stream_status.ssl_status
        conn = self._get_conn_to_ptp_db()
	cursor = conn.cursor()
        try:
            sql = ' '.join("INSERT INTO", _sql_streams_table_columns, _sql_stream_table_values) % \
                (ts.cli_ip, ts.cli_pt, ts.svr_ip, ts.svr_pt, int(ts.bytes_to_svr), int(ts.bytes_to_cli),
                 self._epoch_to_datetime(ts.ts_first_pkt), self._epoch_to_datetime(ts.ts_last_pkt),
                 int(ss.client_hello), int(ss.client_change_cipher_spec), int(ss.server_hello), str(ss.version), 
                 str(ss.cipher), int(ss.server_change_cipher_spec))

            cursor.execute(sql)
            conn.commit()
        except MySQLdb.OperationalError as e:
            print("Insert failed: ", e)
            conn.rollback()
        finally:
            cursor.close()
            conn.close()

    def persist_stream_old(self, stream_status):
        tcp_status = stream_status.tcp_status
        ssl_status = stream_status.ssl_status
        conn = self._get_conn_to_ptp_db()
	cursor = conn.cursor()
        try:
            sql = """insert into 
                    streams (cli_ip, cli_pt, svr_ip, svr_pt, bytes_to_svr, 
                    bytes_to_cli, ts_first_pkt, ts_last_pkt) 
                   values (inet6_aton(\'%s\'), %d, inet6_aton(\'%s\'), 
                    %d, %d, %d, '%s', '%s')""" % \
                   (tcp_status.cli_ip, tcp_status.cli_pt, tcp_status.svr_ip, tcp_status.svr_pt, 
                    tcp_status.bytes_to_svr, tcp_status.bytes_to_cli,
                    tcp_status.ts_first_pkt, tcp_status.ts_last_pkt)
            cursor.execute(sql)
            conn.commit()
        except MySQLdb.OperationalError as e:
            print("Insert failed: ", e)
            conn.rollback()
        finally:
            cursor.close()
            conn.close()

    def select_all_streams_old(self):
        streams = []
        rows = self._select_all_stream_rows()
        for row in rows:
            id, cli_ip, cli_pt, svr_ip, svr_pt, bytes_to_svr, bytes_to_cli, \
                ts_first_pkt, ts_last_pkt = row
            tcp_status = TCP_Status(cli_ip=cli_ip, cli_pt=cli_pt, svr_ip=svr_ip,
                svr_pt=svr_pt, bytes_to_svr=bytes_to_svr, bytes_to_cli=bytes_to_cli,
                ts_first_pkt=ts_first_pkt, ts_last_pkt=ts_last_pkt)
            ssl_status = SSL_Status()
            stream_status = Stream_Status(id=id, tcp_status=tcp_status, \
                    ssl_status=ssl_status).get_flattened()
            streams.append(stream_status)
        return streams
    
    def select_all_streams(self):
        streams = []
        rows = self._select_all_stream_rows()
        for row in rows:
            id, cli_ip, cli_pt, svr_ip, svr_pt, bytes_to_svr, bytes_to_cli, \
                ts_first_pkt, ts_last_pkt = row
            tcp_status = TCP_Status(cli_ip=cli_ip, cli_pt=cli_pt, svr_ip=svr_ip,
                svr_pt=svr_pt, bytes_to_svr=bytes_to_svr, bytes_to_cli=bytes_to_cli,
                ts_first_pkt=ts_first_pkt, ts_last_pkt=ts_last_pkt)
            ssl_status = SSL_Status()
            stream_status = Stream_Status(id=id, tcp_status=tcp_status, \
                    ssl_status=ssl_status).get_flattened()
            streams.append(stream_status)
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
        stream_status = None
        print "quad_tuple:", quad_tuple
        #self.log("select_stream_by_quad_tuple: quad_tuple: " % str(quad_tuple))
        row = self._select_stream_row_by_quad_tuple(quad_tuple)
        print "row:", row
        #self.log("select_stream_by_quad_tuple: row: " % str(row))

        if row:
            id, cli_ip, cli_pt, svr_ip, svr_pt, bytes_to_svr, bytes_to_cli, \
                ts_first_pkt, ts_last_pkt = row
            tcp_status = TCP_Status(cli_ip=cli_ip, cli_pt=cli_pt, svr_ip=svr_ip,
                svr_pt=svr_pt, bytes_to_svr=bytes_to_svr, bytes_to_cli=bytes_to_cli,
                ts_first_pkt=ts_first_pkt, ts_last_pkt=ts_last_pkt)
            ssl_status = SSL_Status()
            stream_status = Stream(id=id, tcp_status=tcp_status, ssl_status=ssl_status)

        return stream_status
        
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

    def clear_streams(self):
        conn = self._get_conn_to_ptp_db()
	cursor = conn.cursor()
        try:
            sql =  "delete from streams" 
            cursor.execute(sql)
            conn.commit()
        except MySQLdb.OperationalError as e:
            print("Delete failed: ", e)
            conn.rollback()
        finally:
            cursor.close()
            conn.close()

    def update_stream(self, stream_status):
        conn = self._get_conn_to_ptp_db()
	cursor = conn.cursor()
        ts = stream_status.tcp_status
        ss = stream_status.ssl_status
        stream_tuple = (ts.cli_ip, ts.cli_pt, ts.svr_ip, ts.svr_pt, \
            ts.bytes_to_svr, ts.bytes_to_cli, ts.ts_first_pkt, ts.ts_last_pkt)

        try:
            sql =  """update streams 
                    set cli_ip = inet6_aton(\'%s\'), cli_pt = %d, 
                        svr_ip = inet6_aton(\'%s\'), svr_pt = %d,
                        bytes_to_svr = %d, bytes_to_cli = %d,
                        ts_first_pkt = %d, ts_last_pkt = %d
                    where id = %d""" % stream_tuple
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

    def create_table_streams_old(self):
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

    def create_table_streams(self):
        conn = self._get_conn_to_ptp_db()
        cursor = conn.cursor()

        sql = """create table streams (id int not null primary key auto_increment,
            cli_ip varbinary(16),
            cli_pt int(5),
            svr_ip varbinary(16),
            svr_pt int(5), 
            bytes_to_cli int(10),
            bytes_to_svr int(6),
            ts_first_pkt datetime, 
            ts_last_pkt datetime, 
            ssl_cli_hello bool,
            ssl_cli_ccs bool,
            ssl_svr_hello bool,
            ssl_version varbinary(16),
            ssl_cipher varbinary(16),
            ssl_svr_ccs bool )"""

        cursor.execute(sql)
	cursor.close()
        conn.close()


    def log(self, msg):
        self._logger.log(msg)

