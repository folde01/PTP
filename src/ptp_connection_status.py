from ptp_constants import Constants

class Stream_Status(object):
    def __init__(self, **kwargs):
        self.id = kwargs.get('id', None)
        self.tcp_status = kwargs.get('tcp_status', None)
        self.ssl_status = kwargs.get('ssl_status', None)

    def get_stream_tuple(self):
        pass

    def __repr__(self):
        return "<%s:%d %s:%d, bytes_to_svr: %d, bytes_to_cli: %d, ts_first_pkt: %.3f, ts_last_pkt: %.3f>" % \
        (self.tcp_status.cli_ip, self.tcp_status.cli_pt, self.tcp_status.svr_ip, \
            self.tcp_status.svr_pt, self.tcp_status.bytes_to_svr, \
            self.tcp_status.bytes_to_cli, self.tcp_status.ts_first_pkt, \
            self.tcp_status.ts_last_pkt)

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
