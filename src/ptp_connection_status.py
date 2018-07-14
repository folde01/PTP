from ptp_constants import Constants

class Stream_Status(object):
    def __init__(self, **kwargs):
        self.id = kwargs.get('id', None)
        self.tcp_status = kwargs.get('tcp_status', None)
        self.ssl_status = kwargs.get('ssl_status', None)

    def get_stream_tuple(self):
        pass

    def __repr__(self):
        return "<id: %d, %s:%d, %s:%d, bytes_to_svr: %d, bytes_to_cli: %d, ts_first_pkt: %s, ts_last_pkt: %s>" % \
        (self.id, self.tcp_status.cli_ip, self.tcp_status.cli_pt, self.tcp_status.svr_ip, \
            self.tcp_status.svr_pt, self.tcp_status.bytes_to_svr, \
            self.tcp_status.bytes_to_cli, self.tcp_status.ts_first_pkt, \
            self.tcp_status.ts_last_pkt)

    def get_flattened(self):
        """Returns an object with attribute/value pairs needed to create a row in an 
        HTML table of streams."""
        ts=self.tcp_status
        flattened = Stream_Flattened(
                cli_ip = ts.cli_ip,
                cli_pt = ts.cli_pt,
                svr_ip = ts.svr_ip,
                svr_pt = ts.svr_pt,
                bytes_to_svr = ts.bytes_to_svr,
                bytes_to_cli = ts.bytes_to_cli,
                ts_first_pkt = ts.ts_first_pkt,
                ts_last_pkt = ts.ts_last_pkt)
        return flattened

class Stream_Flattened(object):
    """An object made of arbitrary attribute/value pairs.
    Credit to Alex Martelli: 
    http://code.activestate.com/recipes/52308-the-simple-but-handy-collector-of-a-bunch-of-named/
    """
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class TCP_Status(object):
    def __init__(self, **kwargs):
        self.cli_ip = kwargs.get('cli_ip', None)
        self.cli_pt = kwargs.get('cli_pt', None)
        self.svr_ip = kwargs.get('svr_ip', None)
        self.svr_pt = kwargs.get('svr_pt', None)
        self.bytes_to_svr = kwargs.get('bytes_to_svr', None)
        self.bytes_to_cli = kwargs.get('bytes_to_cli', None)
        constants = Constants()
        self.ts_first_pkt = kwargs.get('ts_first_pkt', constants.DEFAULT_TS_FIRST_PKT)
        self.ts_last_pkt = kwargs.get('ts_last_pkt', constants.DEFAULT_TS_LAST_PKT)

    def get_quad_tuple(self):
        return (self.tcp_status.cli_ip, self.tcp_status.cli_pt, self.tcp_status.svr_ip, self.tcp_status.svr_pt)

    def get_tcp_tuple(self):
        return (self.cli_ip, self.cli_pt, self.svr_ip, self.svr_pt, \
                self.bytes_to_svr, self.bytes_to_cli, self.ts_first_pkt, self.ts_last_pkt)

class SSL_Status(object):
    def __init__(self, **kwargs):
        self.ssl_handshake_observed = kwargs.get('ssl_handshake_observed', None)
        self.ssl_version = kwargs.get('ssl_version', None)
        self.ssl_cipher = kwargs.get('ssl_cipher', None)

    def get_ssl_tuple(self):
        return (self.ssl_handshake_observed, self.ssl_version, self.ssl_cipher)
