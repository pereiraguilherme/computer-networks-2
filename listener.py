import socket, sys
from socket import AF_PACKET, SOCK_RAW
from struct import *


def get_mac_addr(bytes_addr):
        bytes_str = map('{:02x}'.format, bytes_addr)
        mac_addr = ':'.join(bytes_str).upper()
        return mac_addr

def unpack_eth_header(data):
        dst_mac, src_mac, proto = unpack('!6s6sH', data)
        return get_mac_addr(dst_mac),get_mac_addr(src_mac), socket.htons(proto), data[:14]

def unpack_ipv6_header(data):
        sub_packet_1, sub_packet_2, src_addr, dst_addr = unpack('!II16s16s', data[:40])
        bits_packet_1 = "{:32b}".format(sub_packet_1) 
        version2 = bits_packet_1[:4]
        traffic_class2 = bits_packet_1[4:12]
        flow_label2 = bits_packet_1[12:32]
        print('Version: {}'.format(int(version2,2)))
        print('Traffic: {}'.format(int(traffic_class2,2)))
        print('Flow: {}'.format(int(flow_label2,2)))

        bits_packet_2 = "{:32b}".format(sub_packet_2)
        payload_lenght2 = bits_packet_2[:16]
        next_header2 = bits_packet_2[16:24]
        hop_limit2 = bits_packet_2[24:32]
        print('Payload: {}'.format(int(payload_lenght2,2)))
        print('Next: {}'.format(int(next_header2,2)))
        print('hop: {}'.format(int(hop_limit2,2)))

def unpack_tcp_header(data):
        src_port, dest_port, sequence, acknowledgment, offset_reserved_flags, tcp_flags, window, tcp_checksum, urg_ptr = unpack('!HHLLBBHHH', data)
        print(src_port)
        print(dest_port)
        offset = (offset_reserved_flags >> 12) * 4
        flag_urg = (tcp_flags & 32) >> 5
        flag_ack = (tcp_flags & 16) >> 4
        flag_psh = (tcp_flags & 8) >> 3
        flag_rst = (tcp_flags & 4) >> 2
        flag_syn = (tcp_flags & 2) >> 1
        flag_fin = tcp_flags & 1

        # identficiar tipo de ataque
        print(flag_syn)
        print(flag_ack)

def listener():
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        print("Start listener")
        while True:
                raw_packet, addr = conn.recvfrom(65535)
                dst_mac, src_mac, eth_proto, data = unpack_eth_header(raw_packet[:14])
                if eth_proto == 56710:
                        print('Destinantion: {}, Source:{}, Protocol:{}'.format(dst_mac, src_mac,eth_proto))    
                        unpack_ipv6_header(raw_packet[14:54])
                        unpack_tcp_header(raw_packet[54:74])

listener()