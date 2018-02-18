import nids

class Analyser:

    def __init__(self, sniffer):
        self._sniffer = sniffer
        self._results = []


    def results(self):
        self._analyse_pcapfile(self._pcap_filename())
        return self._results


    def _pcap_filename(self):
        return self._sniffer.pcap_filename()


    def _analyse_pcapfile(self, pcap_filename):
        nids.param("scan_num_hosts", 0) # disable portscan detection
        nids.chksum_ctl([('0.0.0.0/0', False)]) # disable checksumming
        nids.param("filename", pcap_filename)
        nids.init()
        nids.register_tcp(self._tcpStreamCallback)
        nids.run()


    def _tcpStreamCallback(self, tcpStream):
        if tcpStream.nids_state == nids.NIDS_JUST_EST:
            result = str(tcpStream.addr) + " -- TCP stream started"
            self._results.append(result)
            tcpStream.client.collect = 1
            tcpStream.server.collect = 1
        elif tcpStream.nids_state == nids.NIDS_DATA:
            tcpStream.discard(0)
            result = str(tcpStream.addr) + " -- bytes to server: " + str(tcpStream.server.count)
            self._results.append(result)
            result = str(tcpStream.addr) + " -- bytes to client: " + str(tcpStream.client.count)
            self._results.append(result)
        elif tcpStream.nids_state in (nids.NIDS_TIMEOUT, nids.NIDS_CLOSE, nids.NIDS_RESET):
            result = str(tcpStream.addr) + " -- bytes to server: " + str(tcpStream.server.count)
            self._results.append(result)
            result = str(tcpStream.addr) + " -- bytes to client: " + str(tcpStream.client.count)
            self._results.append(result)
