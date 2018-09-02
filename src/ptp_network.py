import psutil

class Network(object):

    # when using emulator, nic_name=tap0, cli_ip=10.0.2.15
    #def __init__(self, nic_name='tap0', cli_ip='10.0.2.15'):
    def __init__(self, nic_name='lo', cli_ip='10.0.2.15'):
        self._nic_name = nic_name
        self._cli_ip = cli_ip
        self._sniffer_stop_eth = '00:00:00:03:02:01'
        self._sniffer_stop_ip = '10.11.12.13' 

    def get_nic_name(self):
        return self._nic_name

    def get_cli_ip(self):
        return self._cli_ip

    def get_host_ip(self):
	nic_name = self.get_nic_name()
        interfaces = psutil.net_if_addrs()
        nic = ''

        try:
            nic = interfaces[nic_name]
        except KeyError:
            print 'Target device not configured properly. No network interface with this name:', nic_name 

        for snic in nic:
            if snic.family == 2:
                return snic.address
        return None

    def get_stop_eth(self):
        return self._sniffer_stop_eth 

    def get_stop_ip(self):
        return self._sniffer_stop_ip 
