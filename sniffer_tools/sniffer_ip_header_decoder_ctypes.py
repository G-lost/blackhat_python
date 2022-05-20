from ctypes import *
import socket
import struct


class IP(Structure):
    _fields_ = [
        ("version",        c_ubyte,    4),
        ("headerLen",      c_ubyte,    4),
        ("typeOfService",  c_ubyte,    8),
        ("len",            c_ushort,  16),
        ("id",             c_ushort,  16),
        ("flag",           c_ubyte,    3),
        ("fragmentOffset", c_ubyte,   13),
        ("ttl",            c_ubyte,    8),
        ("protocol_num",   c_ubyte,    8),
        ("sum",            c_ushort,  16),
        ("src",            c_uint32,  32),
        ("dst",            c_uint32,  32),
    ]

    def __new__(cls, socket_buffer = None):
        return cls.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer = None):
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))

        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:
            print('%s %s is Unknown Protocol', e, self.protocol_num)
            self.protocol = self.protocol_num