import imp


import ipaddress
import struct

class IP:
    def __init__(self, buff = None) -> None:
        header = struct.pack('<BBHHHBBH4s4s', buff)
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
            self.protocol = self.protocol_num