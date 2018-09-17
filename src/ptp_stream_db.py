from __future__ import print_function
from datetime import datetime
import time
import MySQLdb
from ptp_connection_status import Stream_Status, TCP_Status, SSL_Status, Stream_Flattened
import sys
from ptp_logger import Logger


class Stream_DB(object):
    """Stores and retrieves traffic analysis data in a MySQL database. One table is
    used, with one row per TCP connection. There is a small number of columns,
    and a single table avoids performance issues caused by joins.
    """

    def __init__(self):
        self._sql_streams_table_columns = \
            """streams (cli_ip, cli_pt, svr_ip, svr_pt, bytes_to_svr, bytes_to_cli, ts_first_pkt, ts_last_pkt, ssl_cli_hello, ssl_cli_ccs, ssl_svr_hello, ssl_version, ssl_cipher, ssl_svr_ccs, is_encrypted)"""

        self._sql_stream_table_values = \
            """VALUES (inet6_aton(\'%s\'), %d, inet6_aton(\'%s\'), %d, %d, %d, '%s', '%s', %d, %d, %d, '%s', '%s', %d, '%s')"""


    def select_all_streams(self):
        """Retrieves all rows from database"""
        conn = self._get_conn_to_ptp_db()
	cursor = conn.cursor()

	sql =  """SELECT id, inet6_ntoa(svr_ip), bytes_to_svr, bytes_to_cli, is_encrypted
                    FROM streams
                    ORDER BY bytes_to_cli DESC;"""

	cursor.execute(sql)
	rows = cursor.fetchall()
	cursor.close()
        conn.close()
	return rows

    def persist_streams(self, stream_statuses):
        """Stores a set of Stream_Status objects"""
        conn = self._get_conn_to_ptp_db()
	cursor = conn.cursor()
        try:
            for stream_status in stream_statuses: 
                ts = stream_status.tcp_status
                ss = stream_status.ssl_status
                sql = ' '.join(["INSERT INTO", self._sql_streams_table_columns, self._sql_stream_table_values]) % \
                    (ts.cli_ip, ts.cli_pt, ts.svr_ip, ts.svr_pt, int(ts.bytes_to_svr), int(ts.bytes_to_cli),
                     self._epoch_to_datetime(ts.ts_first_pkt), self._epoch_to_datetime(ts.ts_last_pkt),
                     ss.ssl_cli_hello, ss.ssl_cli_ccs, ss.ssl_svr_hello, ss.ssl_version, 
                     ss.ssl_cipher, ss.ssl_svr_ccs, ss.is_encrypted)
 
                cursor.execute(sql)
            conn.commit()
        except MySQLdb.OperationalError as e:
            print("Insert failed: ", e)
            conn.rollback()
        finally:
            cursor.close()
            conn.close()


    def _epoch_to_datetime(self, epoch_seconds):
        date = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(epoch_seconds))
        return date


    def get_encryption_details_row(self, conn_id):
        """Retrieve connection's encryption details"""
        conn = self._get_conn_to_ptp_db()
	cursor = conn.cursor()
	sql =  """SELECT is_encrypted, ssl_version, ssl_cipher 
                  FROM streams
                  WHERE id = %s"""
	cursor.execute(sql, (conn_id,))
	row = cursor.fetchone()
	cursor.close()
        conn.close()
	return row


    def get_connection_details_row(self, conn_id):
        """Retrieve connection's TCP/IP details"""
        conn = self._get_conn_to_ptp_db()
	cursor = conn.cursor()
	sql =  """SELECT inet6_ntoa(cli_ip), cli_pt, inet6_ntoa(svr_ip), svr_pt,
                    ts_first_pkt, ts_last_pkt
                  FROM streams
                  WHERE id = %s"""
	cursor.execute(sql, (conn_id,))
	row = cursor.fetchone()
	cursor.close()
        conn.close()
	return row


    def clear_streams(self):
        """Delete all rows"""
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
            ssl_version varbinary(64),
            ssl_cipher varbinary(128),
            ssl_svr_ccs bool,
            is_encrypted varbinary(16) )"""

        cursor.execute(sql)
	cursor.close()
        conn.close()


    def log(self, msg):
        self._logger.log(msg)

