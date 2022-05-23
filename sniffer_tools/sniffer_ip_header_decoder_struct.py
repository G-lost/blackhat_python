import ipaddress
import os
import struct
import socket
import sys


class IP:
    def __init__(self, buff = None) -> None:
        header = struct.unpack('<BBHHHBBH4s4s', buff)
        self.version = header[0] >> 4
        self.headerLen = header[0] & 0xf
        self.typeOfService = header [1]
        self.len = header[2]
        self.id = header[3]
        self.flag = header[4] >> 13
        self.fragmentOffset = header[4] and 0xffff
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header [8]
        self.dst = header [9]

        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:
            print('%s %s is Unknown Protocol', e, self.protocol_num)
            self.protocol = str(self.protocol_num)


def sniff(host):
    if os.name == 'nt':
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP
    
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    print(host)
    sniffer.bind((host, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    
    try:
        while True:
            raw_buffer = sniffer.recvfrom(65535)[0]
            ip_header = IP(raw_buffer[0:20])
            print(f'Protocol: {ip_header.protocol} | {ip_header.src_address} -> {ip_header.dst_address}')

    except KeyboardInterrupt:
        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sys.exit()


def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = str(s.getsockname()[0])
    s.close()
    return ip


if __name__ == '__main__':
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = str(get_ip())
    sniff(host)
