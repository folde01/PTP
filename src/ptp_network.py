import psutil

class Network:

    def get_nic_name(self):
        interfaces = psutil.net_if_addrs()
        interface_names = interfaces.keys()
        for name in interface_names:
            if name.startswith("en"):
                return name
        return None

    def get_cli_ip(self):
	nic_name = self.get_nic_name()
        interfaces = psutil.net_if_addrs()
        nic = interfaces[nic_name]
        for snic in nic:
            if snic.family == 2:
                return snic.address
        return None
