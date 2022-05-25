import ipaddress
import os
import struct
import socket
import sys
import threading
import time


SUBNET = '192.168.31.0/24'
MESSAGE = 'Glost_TAG'


class IP:
    def __init__(self, buff = None) -> None:
        header = struct.unpack('<BBHHHBBH4s4s', buff)
        self.version = header[0] >> 4
        self.headerLen = header[0] & 0xf
        self.typeOfService = header [1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header [8]
        self.dst = header [9]

        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)
        self.real_len = socket.ntohs(self.len)
        self.real_id = socket.ntohs(self.id)
        self.real_offset = socket.ntohs(self.offset)
        self.flag = self.real_offset >> 13 << 1
        self.fragmentOffset = self.real_offset & 0x1fff

        # print(f'version: {self.version}, headerlength: {self.headerLen}, offset: {self.offset}, flags: {self.flag:#x}, foffset: {self.fragmentOffset}')
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:
            print(f'{e} {self.protocol_num} is Unknown Protocol')
            self.protocol = str(self.protocol_num)


class ICMP:
    def __init__(self, buff = None) -> None:
        header = struct.unpack('<BBHHH', buff)
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]


class Scanner:
    def __init__(self, host) -> None:
        self.host = host
        if os.name == 'nt':
            socket_protocol = socket.IPPROTO_IP
        else:
            socket_protocol = socket.IPPROTO_ICMP

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        self.socket.bind((host, 0))
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        if os.name == 'nt':
            self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    def sniff(self):
        host_up = set([f'{str(self.host)} *'])
        try:
            while True:
                raw_buffer = self.socket.recvfrom(65535)[0]
                ip_header = IP(raw_buffer[0:20])
                if ip_header.protocol == 'ICMP':
                    offset = ip_header.headerLen*4
                    buf = raw_buffer[offset:offset+8]
                    icmp_header = ICMP(buf)
                    if icmp_header.code == 3 and icmp_header.type == 3:
                        if ipaddress.ip_address(ip_header.src_address) in ipaddress.IPv4Network(SUBNET):
                            if raw_buffer[len(raw_buffer) - len(MESSAGE):] == bytes(MESSAGE, 'utf8'):
                                tgt = str(ip_header.src_address)
                                if tgt != self.host and tgt not in host_up:
                                    host_up.add(str(ip_header.src_address))
                                    print(f'Host Up: {tgt}')
                
        except KeyboardInterrupt:
            if os.name == 'nt':
                self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

            print('\nUser Interrupted')
            if host_up:
                print(f'\n\nSummary: Host up on {SUBNET}')
            for upHost in sorted(host_up):
                print(f'{upHost}')
            print('')
            sys.exit()


def udp_sender():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        for ip in ipaddress.ip_network(SUBNET).hosts():
            sender.sendto(bytes(MESSAGE, 'utf8'), (str(ip), 65212))


def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = str(s.getsockname()[0])
    print(f'get_ip get ip address: {ip}')
    s.close()
    return ip


if __name__ == '__main__':
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = str(get_ip())
    scanner = Scanner(host)
    time.sleep(3)
    thread = threading.Thread(target=udp_sender)
    thread.start()
    scanner.sniff()
