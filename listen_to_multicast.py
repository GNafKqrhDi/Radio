
#    Radio, The P2P social network that relies on multicast channels
#    Copyright (C) 2022  George Stewart
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

from utils import *
from json import load
import socket
import struct
import sys
from time import sleep

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
    if k not in blocked_words:
        group = socket.inet_pton(socket.AF_INET6, accounts[k]) + ifis
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, group)
sock_addr = socket.getaddrinfo(local_addr, mcast_port, socket.AF_INET6, socket.SOCK_DGRAM)[0][4]
sock.bind(sock_addr)

while True:
    sleep(0.1)
    data, src = sock.recvfrom(10000)
    data = crypto_algo.decrypt(data)
    print(src[0])
    with open('multicast_packet', 'ab') as f:
        f.write(data)
    with open ('multicast_packet_size', 'a+') as f:
        f.write("%d "%(len(data)))
    request_process()
