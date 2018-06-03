class Stream(object):
    def __init__(self, cli_ip, cli_pt, svr_ip,
            svr_pt, bytes_to_svr, bytes_to_cli, ts_first_pkt=-1, ts_last_pkt=-1):
        self.cli_ip = cli_ip
        self.cli_pt = cli_pt
        self.svr_ip = svr_ip
        self.svr_pt = svr_pt
        self.bytes_to_svr = bytes_to_svr
        self.bytes_to_cli = bytes_to_cli
        self.ts_first_pkt = ts_first_pkt
        self.ts_last_pkt = ts_last_pkt
