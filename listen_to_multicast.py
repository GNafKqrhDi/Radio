from utils import *
from json import load
import socket
import struct
import sys
from time import sleep

sleep(2)
N=128

local_addr = "::"
mcast_port = 5000
ifn=str()
try:
    ifn=read("current_dev_name").replace('\n', '')
except FileNotFoundError:
    exit(0)
if ifn=="None":
    exit(0)
current_user = read('current_user')

sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

ifi = socket.if_nametoindex(ifn)
ifis = struct.pack("I", ifi)
sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, ifis)

accounts = dict()
with open("accounts.json") as f:
    accounts=load(f)
if accounts.get(current_user, None)==None:
    exit()
accounts = accounts[current_user]

for k in accounts:
    if k!='time' and k!='ip':
        group = socket.inet_pton(socket.AF_INET6, accounts[k]["multicast"]) + ifis
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, group)
sock_addr = socket.getaddrinfo(local_addr, mcast_port, socket.AF_INET6, socket.SOCK_DGRAM)[0][4]
sock.bind(sock_addr)

while True:
    sleep(0.1)
    data, src = sock.recvfrom(10000)
    data = data
    print(src[0])
    with open('multicast_packet', 'ab') as f:
        f.write(data)
    with open ('multicast_packet_size', 'a+') as f:
        f.write("%d "%(len(data)))
    with open('multicast_packet_ip', 'ab') as f:
        f.write(bytes(ipv6_rmv_dots(exp_ipv6(src[0])), 'ascii'))
    request_process()
