import nids
import unittest

class PacketReader:
    
    def __init__(self, pcap_filename='sniffed.pcap'):
        self._pcap_filename = pcap_filename

    def stream_count(self):
        pass

class TestPacketReader(unittest.TestCase):

    def test_pcap_stream_count_is_3(self):
        pcap_filename = 'pcap/stream_count_is_3.pcap'
        pr = PacketReader(pcap_filename)
        self.assertEqual(pr.stream_count(), 3)

if __name__ == '__main__':
        unittest.main()
