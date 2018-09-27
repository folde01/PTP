import ptp_network_conf

class Network(object):

    # when using emulator, nic_name=tap0, cli_ip=10.0.2.15
    def __init__(self):
        self._sniff_iface_name = ptp_network_conf.sniff_iface 
        self._cli_ip = None 
        self._nic_name = self._sniff_iface_name
        self._gateway_iface_name = ptp_network_conf.gateway_iface
        self._gateway_iface_ip_addr = ptp_network_conf.gateway_iface_ip_addr
        self._sniffer_stop_eth = '00:00:00:03:02:01'
        self._sniffer_stop_ip = '10.11.12.13' 

    def get_nic_name(self):
        return self._nic_name

    def get_sniff_iface_name(self):
        return self._sniff_iface_name

    def get_gateway_iface_name(self):
        return self._gateway_iface_name

    def get_cli_ip(self):
        if self._cli_ip is None:
            if self._sniff_iface_name == 'tap0':
                self._cli_ip = '10.0.2.15'
            else:
                self._cli_ip = self._gateway_iface_ip_addr 
        return self._cli_ip

    def get_host_ip(self):
        return self._gateway_iface_ip_addr

    def get_stop_eth(self):
        return self._sniffer_stop_eth 

    def get_stop_ip(self):
        return self._sniffer_stop_ip 
