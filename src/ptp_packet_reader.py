import nids
import unittest
    
class PacketReader:
    
    def __init__(self, pcap_filename='sniffed.pcap'):
	self._streams = []
	self._analyse_pcapfile(pcap_filename)

    def streams(self):
        return self._streams

    def _analyse_pcapfile(self, pcap_filename):
        nids.param("scan_num_hosts", 0) # disable portscan detection
        nids.chksum_ctl([('0.0.0.0/0', False)]) # disable checksumming
        nids.param("filename", pcap_filename)
        nids.init()
        nids.register_tcp(self._callback_gatherStreamObjects)
        nids.run()

    def _add_stream_if_new(self, stream):
        for s in self._streams: 
            if self._same_stream(stream, s):
               return
        self._streams.append(stream)

    def _same_stream(self, s1, s2):
        ((src_ip_1, src_port_1), (dest_ip_1, dest_port_1)) = s1.addr
        ((src_ip_2, src_port_2), (dest_ip_2, dest_port_2)) = s2.addr
        return (src_ip_1 == src_ip_2 and src_port_1 == src_port_2 and dest_ip_1 == dest_ip_2 and dest_port_1 == dest_ip_2) # todo: make this fail earlier

    def _callback_gatherStreamObjects(self, stream):
        if stream.nids_state == nids.NIDS_JUST_EST:
            stream.client.collect = 1
            stream.server.collect = 1
            self._add_stream_if_new(stream)
        elif stream.nids_state == nids.NIDS_DATA:
            stream.discard(0)

class TestPacketReader(unittest.TestCase):

    def test_pcap_stream_count_is_17(self):
        pcap_filename = 'stream_count_is_17.pcap'
        pr = PacketReader(pcap_filename)
        self.assertEqual(len(pr.streams()), 17)

    def test_pcap_stream_count_is_3(self):
        pcap_filename = 'stream_count_is_3.pcap'
        pr = PacketReader(pcap_filename)
        self.assertEqual(len(pr.streams()), 3)


if __name__ == '__main__':
	unittest.main()
