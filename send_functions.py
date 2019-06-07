import socket, sys
from socket import AF_PACKET, SOCK_RAW
from struct import *

def sendeth(eth_frame, interface = "enp4s0"):
	"""Send raw Ethernet packet on interface."""
	s = socket.socket(AF_PACKET, SOCK_RAW)
	s.bind((interface, 0))
	return s.send(eth_frame)

def checksum(msg):
	s = 0
	# loop taking 2 characters at a time
	for i in range(0, len(msg), 2):
		w = (ord(msg[i]) << 8) + (ord(msg[i+1]))
		s = s + w

	s = (s >> 16) + (s & 0xffff)
	s = ~s & 0xffff

	return s


def build_ipv6_header(source_addr, dest_addr):
	version = 6
	traffic_class = 0
	sub_packet  = version << 8 + traffic_class
	flow_label = 0
	sub_packet_1 = sub_packet << 20 + flow_label

	payload_lenght = 20 
	
	next_header = socket.IPPROTO_TCP
	hop_limit = 255
	sub_packet_2 = (payload_lenght << 16) + (next_header << 8) + hop_limit
	
	ip_header = pack('!II' , sub_packet_1,sub_packet_2,source_addr,dest_addr)
	return ip_header


if __name__ == "__main__":
	# src=fe:ed:fa:ce:be:ef, dst=52:54:00:12:35:02, type=0x0800 (IP)
	dst_mac = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
	src_mac = [0x00, 0x0a, 0x11, 0x11, 0x22, 0x22]
	
	# Ethernet header
	eth_header = pack('!6B6BH', dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5], 
		src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5], 0x86DD)
	source_ip = '10.32.143.171 '
	dest_ip = '10.32.143.171 '			# or socket.gethostbyname('www.google.com')

	
	source_addr = socket.inet_pton(socket.AF_INET6,"fe80::a61f:72ff:fef5:9086")
	dest_addr = socket.inet_pton(socket.AF_INET6,"fe80::a61f:72ff:fef5:9086")
	
	ip_header = build_ipv6_header(source_addr, dest_addr)

	# tcp header fields
	source = 1234   # source port
	dest = 33   # destination port
	seq = 0
	ack_seq = 0
	doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes

	#tcp flags
	fin = 0
	syn = 1
	rst = 0
	psh = 0
	ack = 0
	urg = 0
	window = socket.htons(5840)		# maximum allowed window size
	check = 0
	urg_ptr = 0
	 
	offset_res = (doff << 4) + 0
	tcp_flags = fin + (syn << 1) + (rst << 2) + (psh <<3) + (ack << 4) + (urg << 5)
	 
	# the ! in the pack format string means network order
	tcp_header = pack('!HHLLBBHHH' , source, dest, seq, ack_seq, offset_res, tcp_flags,  window, check, urg_ptr)
	 
	# pseudo header fields
	source_address = socket.inet_aton( source_ip )
	dest_address = socket.inet_aton(dest_ip)
	placeholder = 0
	protocol = socket.IPPROTO_TCP
	tcp_length = len(tcp_header)
	 
	psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);
	psh = psh + tcp_header;
	 
	tcp_checksum = checksum(psh)
	 
	# make the tcp header again and fill the correct checksum
	tcp_header = pack('!HHLLBBHHH' , source, dest, seq, ack_seq, offset_res, tcp_flags,  window, tcp_checksum , urg_ptr)
	 
	# final full packet - syn packets dont have any data
	packet = eth_header + ip_header + tcp_header
	r = sendeth(packet, "enp4s0")
	print("Sent %d bytes" % r)
