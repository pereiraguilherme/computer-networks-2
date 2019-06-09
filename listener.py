import socket, sys
from socket import AF_PACKET, SOCK_RAW
from struct import *


def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

def unpack_eth_frame(data):
    dst_mac, src_mac, proto = unpack('!6s6sH', data[:14])
    return get_mac_addr(dst_mac),get_mac_addr(src_mac), socket.htons(proto), data[:14]

def listener():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    print("Start listener")
    while True:
        raw_packet, addr = conn.recvfrom(65535)
        dst_mac, src_mac, eth_proto, data = unpack_eth_frame(raw_packet)
        print('Destinantion: {}, Source:{}, Protocol:{}'.format(dst_mac, src_mac,eth_proto))    


listener()