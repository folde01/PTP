import nids

class Analyser:

    def __init__(self, sniffer):
        self._sniffer = sniffer
        self._results = []
        self._streams = []

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
        nids.register_tcp(self._callback_gatherStreamObjects)
        nids.run()
        self._analyse_streams(self._streams)

    def _analyse_streams(self, streams):
        for stream in streams:
            addr = stream.addr
            bytes_to_server = stream.server.count
            bytes_to_client = stream.client.count
            result = str(addr) + " BYTES OUT: " + str(bytes_to_server) + " BYTES IN: " + str(bytes_to_client)
            self._results.append(result)

        
    def _add_stream_if_new(self, stream):
        if stream not in self._streams:
            self._streams.append(stream)

    def _callback_gatherStreamObjects(self, tcpStream):
        self._add_stream_if_new(tcpStream)
        if tcpStream.nids_state == nids.NIDS_JUST_EST:
            tcpStream.client.collect = 1
            tcpStream.server.collect = 1
        else: 
            tcpStream.discard(0)

'''
    def _streams_to_servers(self):
        servers = []
        for stream in self._streams:
            ((src_ip,src_port),(dest_ip,dest_port)) = stream.addr
            server = Server(dest_ip, dest_port, stream.server.count, stream.client.count)
            if server not in servers:
                servers.append(server)
            else: 

class Server:

    def __init__(self, ip_addr, tcp_port, bytes_to_server, bytes_to_client):
        self.ip_addr = ip_addr
        self.tcp_port = tcp_port
        self.bytes_to_server = bytes_to_server 
        self.bytes_to_client = bytes_to_client 

    def _total_bytes_from_client(self):
        return sum([ stream.server.count for stream in self._streams]) 

    def _total_bytes_to_client(self):
        return sum([ stream.client.count for stream in self._streams]) 
'''

'''
    def _save_streams(self):
        for stream in self._streams:
            _save_stream(stream)

    def _save_stream(self, stream):
'''
