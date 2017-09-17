import socket
import struct

addr_long = int("0200A8C0", 16)
hex(addr_long)
struct.pack("<L", addr_long)
socket.inet_ntoa(struct.pack("<L", addr_long))
'192.168.0.2'

pnSeed = [
    0x34bb2958, 0x34b22272, 0x284c48d2, 0x010a8878,
    0x010a8854, 0x68ed0421, 0x6e5001fa, 0x704a39c2,
    0x714efdbe, 0x72d72ed0, 0x73ca9f1c, 0x73d7e9a2,
    0x73d8b17e, 0x7596b911, 0x76be4d45, 0x7782e589,
    0x77893560, 0x7789374c, 0x773150e0, 0x784d393f,
    0x79db7b43, 0x7928763e, 0x7b740689, 0x7d6f8d02,
    0x7d242fef, 0x0d5b2dfa, 0x8682ac58, 0x86c417ee,
    0x88f3329f, 0x8b3be656, 0x8ce0749d, 0x904ced27,
    0x9e457e9c, 0x9e45f85d, 0xac682d73, 0xadefd429,
    0xae4c9ec2, 0xaf9157c8, 0xb0e28fc7, 0xb637d267,
    0xb7595fb4, 0xb8a481ca, 0xb98d1b95, 0xb959f43f,
    0xc2e40b90, 0xd5fe6742, 0xd86364ca, 0xd94f2e9f,
    0xd94f2e9f, 0xdb837aee, 0xdc82eae2, 0xdca0c426,
    0xdd0b1685, 0xdea11aeb, 0xde5c48ae, 0xdf49ea1c,
    0x1b985be9, 0x1f0a9de8, 0x1f862769, 0x22c182dd,
    0x22ca06ce, 0x22e083f8, 0x239c545a, 0x242f89ed,
    0x253b180f, 0x276d7d49, 0x284c48d2, 0x2be98289,
    0x2e00c010, 0x2e79c64a, 0x2ea6cc3e, 0x2f95241d,
    0x2f3400c1, 0x2f5a1703, 0x31230c06, 0x34a60b6c,
    0x34a90b6d, 0x34b22272, 0x34bb1634, 0x34bb2958,
    0x34063da3, 0x3ba8a876, 0x3d64127d, 0x41be2593,
    0x420bb276, 0x497840f9, 0x4ad058a2, 0x4e9d1850,
    0x4e5e20c2, 0x5096a322, 0x54d03240, 0x54195ae4,
    0x598e28dc, 0x5c3f39aa, 0x5d327298
]

default_port = '8168'
# ipv4 in ipv6 prefix
pchIPv4 = bytearray([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff])

def hexToIP(hexNumber):
    addr_long = hexNumber
    hex(addr_long)
    struct.pack(">L", addr_long)
    return socket.inet_ntoa(struct.pack(">L", addr_long))


def ipToV6HexString(addr, port):
    arrays = pchIPv4 + bytearray((int(x) for x in addr.split('.')))
    s = '{{'
    for number in arrays:
        s += str(hex(number))
        s += ','
    s = s[:-1] + '},' + str(port) + '},'
    return s
for number in pnSeed:
    print(ipToV6HexString(hexToIP(number), default_port))