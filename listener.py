import socket, sys
import ipaddress
from socket import AF_PACKET, SOCK_RAW
from struct import *

def check_msg(src_addr, dst_addr, msg_type, msg_history):
        if msg_history:
                for packet in msg_history:
                        if packet["ip_src"] == src_addr and packet["ip_dst"] == dst_addr:
                                if msg_type not in packet["msg_type"]:
                                        packet["msg_type"].append(msg_type)
                                        return
                        else:
                                msg = {
                                        "ip_src": src_addr,
                                        "ip_dst": dst_addr,  
                                        "msg_type": [msg_type],
                                }
                                msg_history.append(msg)         
                                return                      
        else:
                msg = {
                        "ip_src": src_addr,
                        "ip_dst": dst_addr,  
                        "msg_type": [msg_type],
                }
                msg_history.append(msg)         
                return                  
        
      
def check_atk(src_addr, dst_addr, msg_type, atk_history, msg_history):
        for msg in msg_history:
                if msg["ip_src"] == src_addr and msg["ip_dst"] == dst_addr:
                        if len(msg["msg_type"]) == 2:
                                atk_type = check_atk(msg["msg_type"])
                                if atk_history:
                                        for atk in atk_history:
                                                if atk["ip_src"] == src_addr:
                                                        atk["atk_types"].append(atk_type)
                                                        atk["times"] +=1
                                                        if atk["times"] >= 5:
                                                                return True
                                                else:
                                                        new_atk = {
                                                                "ip_src": src_addr,
                                                                "atk_type": atk_type,
                                                                "times": 1
                                                        }
                                                        atk_history.append(new_atk)
                                                        return False
                                else:
                                        new_atk = {
                                        "ip_src": src_addr,
                                        "atk_type": atk_type,
                                        "times": 1
                                        }
                                        atk_history.append(new_atk)
                                        return False
                        else:
                                continue
                else:
                        continue
        return False

# ##urg, ack, psh, rst, syn, fin
# ## syn sequence '000010'
# ## ack sequence '010000'
# ## rst sequence '000100'
# ## fin sequence '000001'
# ## syn/ack sequence '010010'
def check_type(tcp_flags):
        sequence = ''
        for flag in tcp_flags:
                sequence += str(flag)
        print(sequence)
        if '000010' == sequence:
                return 'syn'
        elif '010000' == sequence:
                return 'ack'
        elif '000100' == sequence:
                return 'rst'
        elif '000001' == sequence:
                return 'fin'
        elif '010010' == sequence:
                return 'syn/ack'


def get_mac_addr(bytes_addr):
        bytes_str = map('{:02x}'.format, bytes_addr)
        mac_addr = ':'.join(bytes_str).upper()
        return mac_addr

def get_ipv6_addr(bytes_addr):
        return str(ipaddress.ip_address(bytes_addr))

def unpack_eth_header(data):
        dst_mac, src_mac, proto = unpack('!6s6sH', data)
        return get_mac_addr(dst_mac),get_mac_addr(src_mac), socket.htons(proto), data[:14]

def unpack_ipv6_header(data):
        sub_packet_1, sub_packet_2, src_addr, dst_addr = unpack('!II16s16s', data[:40])
        bits_packet_1 = "{:32b}".format(sub_packet_1) 
        version2 = bits_packet_1[:4]
        traffic_class2 = bits_packet_1[4:12]
        flow_label2 = bits_packet_1[12:32]
        bits_packet_2 = "{:32b}".format(sub_packet_2)
        payload_lenght2 = bits_packet_2[:16]
        next_header2 = bits_packet_2[16:24]
        hop_limit2 = bits_packet_2[24:32]

        return get_ipv6_addr(src_addr), get_ipv6_addr(dst_addr)

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
        flags = []
        flags.append(flag_urg)
        flags.append(flag_ack)
        flags.append(flag_psh)
        flags.append(flag_rst)
        flags.append(flag_syn)
        flags.append(flag_fin)
        return dest_port, flags

def listener():
        msg_history = []
        atk_history = []
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        print("Start listener")
        while True:
                raw_packet, addr = conn.recvfrom(65535)
                dst_mac, src_mac, eth_proto, data = unpack_eth_header(raw_packet[:14])
                if eth_proto == 56710:
                        print('Destinantion: {}, Source:{}, Protocol:{}'.format(dst_mac, src_mac,eth_proto))    
                        src_addr, dst_addr = unpack_ipv6_header(raw_packet[14:54])
                        dst_port, tcp_flags = unpack_tcp_header(raw_packet[54:75])
                        msg_type = check_type(tcp_flags)
                        check_msg(src_addr,dst_addr,msg_type, msg_history)
                        atk = check_atk(src_addr,dst_addr,msg_type, atk_history, msg_history)
                        print(atk)
                        

listener()