from ptp_logger import Logger
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Ether, IP, TCP, sendp, rdpcap, Raw, PacketList, PPP
import threading
import unittest
import os
import time
import pcapy
from socket import ntohs
from struct import unpack
from ptp_packet_sender import Packet_Sender 
from ptp_network import Network 

class Sniffer(object):

    def __init__(self, pcap_filename='sniffed.pcap'):
        self._packets = None
        self._sniffer_thread = None
        self._logger = Logger(logfile="ptp_sniffer.log")
        self._pcap_filename = pcap_filename 
        self._net = Network()
        self._host_ip = self._net.get_host_ip()
        self._stop_eth_addr = self._net.get_stop_eth() 
        #self._nic_name = self._net.get_nic_name()
        self._sniff_iface_name = self._net.get_sniff_iface_name()
        self._cli_ip = self._net.get_cli_ip()

    def get_pcap_filename(self):
        return self._pcap_filename

    def start(self):
        """Start sniffer."""
        self._sniffer_thread = threading.Thread(target=self._run_sniffer_thread)
        self._sniffer_thread.daemon = True
        self.log("Sniffer initialised")
        self._sniffer_thread.start()
        #return self.is_running()

    def _run_sniffer_thread(self):
        nic_name = self._sniff_iface_name
        #print 'sniff nic_name:', nic_name
        #local_ip = self._cli_ip
        cli_ip = self._cli_ip
        #print 'sniff cli_ip:', cli_ip
        #self.log("nic_name=%s; local_ip=%s" % (nic_name, local_ip))
        #nic_name = "ppp0"
        #nic_name = "wlp3s0"
        max_packet_size = 65536
        promiscuous_mode = 1
        # may need to set timeout_ms to something non-zero, 
        # otherwise the underlying (libpcap) packet capture loop iteration 
        # can't complete until packets are actually captured
        timeout_ms = 0 
        cap = pcapy.open_live(nic_name, max_packet_size, promiscuous_mode, timeout_ms)
        #host_ip = self._host_ip
	#bpf_filter = "( host %s and tcp and ( not host %s ) ) or ether dst %s" % (local_ip, host_ip, self._stop_eth_addr)
	bpf_filter = "tcp"
	#bpf_filter = "tcp and host %s" % (cli_ip) # why isn't this working?
        #self.log("bpf_filter=%s" % bpf_filter)
	cap.setfilter(bpf_filter)
	dumper = cap.dump_open(self._pcap_filename)

	while(True):
	    packet_hdr, packet_body = cap.next()
	    if self._is_stop_packet(packet_body, self._stop_eth_addr):
		break
	    dumper.dump(packet_hdr,packet_body)

	del dumper

    '''credit: binary tides'''
    def _eth_addr(self, a):
	b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
	return b

    '''credit: binary tides'''
    def _is_stop_packet(self, packet_body, stop_eth_addr):
        #scapy_pkt = PPP(packet_body)
        #print "scapy_pkt:", scapy_pkt.show()
        eth_header_start_byte = 0
        eth_header_length = 14

        '''
        we need to move forward 2 bytes if using PPP. See
        https://www.wireshark.org/lists/ethereal-users/200412/msg00314.html 
        '''
        if self._sniff_iface_name == 'ppp0':
            print "using ppp0"
	    eth_header_start_byte = 2 

        eth_header_end_byte = eth_header_start_byte + eth_header_length
	eth_header = packet_body[eth_header_start_byte:eth_header_end_byte]
	eth = unpack('!6s6sH' , eth_header)
	eth_protocol = ntohs(eth[2])
	eth_header_bytes = packet_body[0:6]
	eth_addr_str = self._eth_addr(eth_header_bytes)
        #print "eth_addr_str:", eth_addr_str
	if eth_addr_str == stop_eth_addr:
	    print 'Stop packet received'
	    return True
	return False


    def _is_stop_packet2(self, packet_body, stop_eth_addr):
        scapy_pkt = Ether(packet_body)
        print "scapy_pkt:", scapy_pkt.show()
        

    def stop(self):
        """Stop sniffer."""
        self._send_kill_packet()
	if self.is_running():
            time.sleep(1)
            self.stop()

    def pcap_filename(self):
        return self._pcap_filename 

    def _send_kill_packet(self):
        Packet_Sender().send_kill_packet()

    def _send_kill_packet_old(self):
        host_ip = self._host_ip
	#kill_packet = Ether(dst='00:00:00:03:02:01')/IP(dst='10.11.12.13')/TCP()
	kill_packet = Ether(dst=self._stop_eth_addr)/IP(dst=host_ip)/TCP()
	sendp(kill_packet)
	#sendp(kill_packet, iface=self._sniff_iface_name)

    def is_running(self):
        if self._sniffer_thread is None:
            return False
        return self._sniffer_thread.isAlive()
        

    def pcap_file_exists(self):
        return os.path.isfile(self._pcap_filename) 

    def log(self, msg):
        self._logger.log(msg)
