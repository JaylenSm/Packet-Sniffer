import socket
import time
import os
import platform
import ssl
import struct


raw_data_body = None
raw_data_addr = None


class Packet_Sniffer:
    __slots__ = ["interface"]

    def __init__(self, interface="eth0"):
        self.interface = interface

    def _raw_data(self):
        global raw_data_body
        global raw_data_addr
        try:
            conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            conn.bind((self.interface, 0))
            raw_data, addr = conn.recvfrom(65500) 
            #raw_data variable given to the binary string
            #addr variable given to the addr/header portion of the packet
            raw_data_body = raw_data
            raw_data_addr = addr
            temp_list = list()
            print(f"""Byte encoded body:
{raw_data_body}
""")
            print(f"""Byte encoded headers:
{raw_data_addr}
""")
            print(f"""
Hexadecimal format body:
{raw_data_body.hex()}
""")
            [temp_list.append(i.hex()) for i in raw_data_addr if type(i) == bytes] 
            print(f"""Hexadecimal format headers:
{temp_list}
""")
            temp_list = list()
        except KeyboardInterrupt:
            print("""
Sniffing stopped by user!
""")
            time.sleep(2)
            conn.close()
            exit()

    def _local_tcp(self):
        try:
            sniffer_tcp = socket.socket(socket.AF_PACKET,
socket.SOCK_RAW, socket.ntohs(0x0003))
            sniffer_tcp.bind((self.interface, 0))
            raw_data, addr = sniffer_tcp.recvfrom(65535)
            eth_proto = struct.unpack("!H", raw_data[12:14])[0]
            if eth_proto != 0x0800:
                print("""A packet was detected as not IPv4
""")
            ip_header = raw_data[14:34]
            iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
            ip_header_length = (iph[0] & 0x0F) * 4
            protocol = iph[6]
            if protocol == 6:
                try:
                    src_ip = socket.inet_ntoa(iph[8])
                    dest_ip = socket.inet_ntoa(iph[9])
                    tcp_header_start = (14 + ip_header_length)
                    tcp_header = raw_data[tcp_header_start:tcp_header_start + 20]
                    tcph = struct.unpack("!HHLLBBHH", tcp_header)
                    tcp_header_length = (tcph[4] >> 4) * 4
                    full_tcp_header = raw_data[tcp_header_start:tcp_header_start * tcp_header_length]
                    src_port = tcph[0]
                    dest_port = tcph[1]
                    print(f"""TCP Packet

Source IP: {src_ip}
Source Port: {src_port}
Destination IP: {dest_ip}
Destination Port: {dest_port}
""")
                except struct.error:
                    print("""
This TCP/IP packet is too small to display!
""")
        except KeyboardInterrupt:
             print("""
Sniffing stopped by user!
""")
             time.sleep(2)
             sniffer_tcp.close()
             exit()

    def _local_udp(self):
        try:
            sniffer_udp = socket.socket(socket.AF_PACKET,
socket.SOCK_RAW, socket.ntohs(0x0003))
            sniffer_udp.bind((self.interface, 0))
            raw_data, addr = sniffer_udp.recvfrom(65535)
            eth_proto = struct.unpack("!H", raw_data[12:14])[0]
            if eth_proto != 0x0800:
                print("This packet was recognized as not IPv4!")
            ip_header = raw_data[14:34]
            iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
            ip_header_length = (iph[0] & 0x0F) * 4
            protocol = iph[6]
            if protocol == 17:
                try:
                    src_ip = socket.inet_ntoa(iph[8])
                    dest_ip = socket.inet_ntoa(iph[9])
                    udp_header_start = 14 + ip_header_length
                    udp_header = raw_data[udp_header_start:udp_header_start + 8]
                    if len(udp_header) < 8:
                        print("This UDP packet is too small!")
                    udph = struct.unpack("!HHHH", udp_header)
                    src_port = udph[0]
                    dest_port = udph[1]
                    length = udph[2]
                    print(f"""UDP Packet:
Source IP: {src_ip}
Source Port: {src_port}
Destination IP: {dest_ip}
Destination Port: {dest_port}
Length: {length}
""")
                except UnboundLocalError:
                    print("""
Something went wrong with displaying this UDP packet!
""")
        except KeyboardInterrupt:
            print("""
Sniffing stopped by user!
""")
            time.sleep(2)
            sniffer_udp.close()
            exit()




__all__ = ["Packet_Sniffer", "raw_data_body", "raw_data_addr"]

if __name__ == "__main__":
    pass