
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

import socket
import sys
from time import sleep
from utils import *
from json import load
from os import popen

current_user = read('current_user').replace('\n', '')
if current_user=='None':
    exit()
accounts = dict()
with open("accounts.json", 'r') as f:
    accounts = load(f)[current_user]

neighbour = dict()

info = socket.getaddrinfo("::1", 2222, socket.AF_INET6, socket.SOCK_STREAM,0, socket.AI_PASSIVE)
af, socktype, proto, canonname, sa = info[0]
sock = socket.socket(af, socktype, proto)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
sock.bind(sa)
sock.listen()

while True:
    sleep(0.1)
    conn, addr = sock.accept()
    x = conn.recv(1).decode()
    if x=='1':
        sleep(5)
        fnames = ["server_packet", "multicast_packet"]
        ls = list()
        data_size = list()
        for i in range(2):
            with open(fnames[i], 'r+b') as f:
                data_size = list()
                with open(fnames[i]+'_size', 'r') as f2:
                    data_size = list(map(int, f2.read().split()))
                pos = 0
                for size in data_size:
                    data = f.read(size)
                    if len(data)>0:
                        try:
                            timestamp = float(data[32:32+25].decode())
                            ls.append((timestamp, pos, size, i))
                        except ValueError:
                            pass
                        pos+=size
        ls = sorted(ls)
        print(ls)
        for elem in ls:
            data = readb(fnames[elem[3]],elem[1], elem[2])
            with open('neighbour.json', 'r') as f:
                neighbour = load(f)
            if elem[3]==0:
                process_server(data, current_user, accounts, neighbour)
            else:
                process_multicast(data, current_user, accounts)
        for i in range(2):
            with open(fnames[i], 'wb+') as f:
                f.write(b'')
            with open(fnames[i]+'_size', 'w') as f:
                f.write('')
            with open(fnames[i]+'_ip', 'wb+') as f:
                f.write(b'')
