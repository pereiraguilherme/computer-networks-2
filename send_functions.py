import socket, sys
from socket import AF_PACKET, SOCK_RAW
from struct import *

def sendeth(eth_frame, interface = "enp7s0"):
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


"""
Function that build ipv6 header
	@paramter source_addr - source address (check ifconfig)
	@paramter dest_addr - destination address
	@return ipv6 header in hexadecimal
"""
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
	
	ip_header = pack('!II' , sub_packet_1,sub_packet_2)
	return ip_header + source_addr + dest_addr

"""
Function that build tcp header
	@parameter source - source port 
	@paramter dest - destination port 
	@paramter source_ip - source ip (check ifconfig)
	@parameter dest_ip - destination ip 
	@return tcp header in hexadecimal
"""
def build_tcp_header(source, dest, source_ip, dest_ip):
	# tcp header fields
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
	 
	psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length)
	psh = psh + tcp_header
	 
	tcp_checksum = checksum(psh)
	 
	# make the tcp header again and fill the correct checksum
	return pack('!HHLLBBHHH' , source, dest, seq, ack_seq, offset_res, tcp_flags,  window, tcp_checksum , urg_ptr)
	 

if __name__ == "__main__":
	# src=fe:ed:fa:ce:be:ef, dst=52:54:00:12:35:02, type=0x0800 (IP)
	dst_mac = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
	src_mac = [0x00, 0x0a, 0x11, 0x11, 0x22, 0x22]
	
	# Ethernet header
	eth_header = pack('!6B6BH', dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5], 
		src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5], 0x86DD)
	
	source_ip = '192.168.11.17'
	dest_ip = '192.168.11.17'			# or socket.gethostbyname('www.google.com')

	
	source_addr = socket.inet_pton(socket.AF_INET6,"fe80::8491:bfdf:4d23:9a9b")
	dest_addr = socket.inet_pton(socket.AF_INET6,"fe80::8491:bfdf:4d23:9a9b")
	
	ip_header = build_ipv6_header(source_addr, dest_addr)
	tcp_header = build_tcp_header(1234, 44, source_ip, dest_ip)

	# final full packet - syn packets dont have any data
	packet = eth_header + ip_header + tcp_header
	r = sendeth(packet, "enp7s0")
	print("Sent %d bytes" % r)
