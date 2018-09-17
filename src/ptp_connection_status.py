from ptp_constants import Constants, Is_Encrypted_Enum

class Stream_Status(object):
    """For storing the full analysis of a TCP connection
    including TCP and SSL-related information."""
    def __init__(self, **kwargs):
        self.id = kwargs.get('id', None)
        self.tcp_status = kwargs.get('tcp_status', None)
        self.ssl_status = kwargs.get('ssl_status', None)
        self._const = Constants()


    def __repr__(self):
        return "<id: %d, %s:%d, %s:%d, bytes_to_svr: %d, bytes_to_cli: %d, ts_first_pkt: %s, ts_last_pkt: %s>" % \
        (self.id, self.tcp_status.cli_ip, self.tcp_status.cli_pt, self.tcp_status.svr_ip, \
            self.tcp_status.svr_pt, self.tcp_status.bytes_to_svr, \
            self.tcp_status.bytes_to_cli, self.tcp_status.ts_first_pkt, \
            self.tcp_status.ts_last_pkt)


class TCP_Status(object):
    """For storing the TCP/IP info from a TCP connection
    """
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
    """For storing the SSL analysis of a TCP connection
    """
    def __init__(self, **kwargs):
        self.ssl_cli_hello = kwargs.get('ssl_cli_hello', False)
        self.ssl_cli_ccs = kwargs.get('ssl_cli_ccs', False)
        self.ssl_svr_hello = kwargs.get('ssl_svr_hello', False)
        self.ssl_version = kwargs.get('ssl_version', "Version information not available")
        self.ssl_cipher = kwargs.get('ssl_cipher', "Cipher information not available")
        self.ssl_svr_ccs = kwargs.get('ssl_svr_ccs', False)
        self.is_encrypted = kwargs.get('is_encrypted', Is_Encrypted_Enum().UNASSESSED)

    def set_client_hello(self, client_hello_seen):
        self.ssl_cli_hello = client_hello_seen


    def show(self):
        print "ssl_cli_hello:", str(self.ssl_cli_hello), "\n", \
                "ssl_cli_ccs:", str(self.ssl_cli_ccs), "\n", \
                "ssl_svr_hello:", str(self.ssl_svr_hello), "\n", \
                "ssl_version:", str(self.ssl_version), "\n", \
                "ssl_cipher:", str(self.ssl_cipher), "\n", \
                "ssl_svr_ccs:", str(self.ssl_svr_ccs), "\n" \
                "is_encrypted:", str(self.is_encrypted), "\n" \

