from ptp_constants import Constants

class Stream(object):

#    def __init__(self, id, cli_ip, cli_pt, svr_ip,
#            svr_pt, bytes_to_svr, bytes_to_cli, ts_first_pkt, ts_last_pkt):
#        self.id = id
#        self.cli_ip = cli_ip
#        self.cli_pt = cli_pt
#        self.svr_ip = svr_ip
#        self.svr_pt = svr_pt
#        self.bytes_to_svr = bytes_to_svr
#        self.bytes_to_cli = bytes_to_cli
#        self.ts_first_pkt = ts_first_pkt
#        self.ts_last_pkt = ts_last_pkt

    def __init__(self, **kwargs):
        self.id = kwargs.get('id', None)
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
        return (self.cli_ip, self.cli_pt, self.svr_ip, self.svr_pt)

    def get_stream_tuple(self):
        return (self.cli_ip, self.cli_pt, self.svr_ip, self.svr_pt, self.bytes_to_svr, self.bytes_to_cli,
            self.ts_first_pkt, self.ts_last_pkt)

