
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
import socket
from json import dump, load
from time import sleep
current_user = read("current_user").replace('\n', '')
accounts = dict()
with open("accounts.json") as f:
    accounts=load(f)
if accounts.get(current_user, None)==None:
    exit()
accounts = accounts[current_user]
if accounts['ip']=='None':
    exit()
neighbour = dict()
with open('neighbour.json', 'r') as f:
    neighbour = load(f)
login = bool(int(read("login")))
if not login:
    write("login", '1')
    for acc in accounts:
        if acc!='time' and acc!='ip':
            print(acc)
            if neighbour.get(acc, None)==None:
                neighbour[acc] = dict()
            neighbour[acc]['addrs'] = [ip for ip in get_random_ips(10, acc) if ip !=accounts['ip']]
            neighbour[acc]['count'] = 0
            neighbour[acc]['type'] = '3' if bool(int(read('has_accounts@'+acc))) else '8'

    with open("neighbour.json", 'w+') as f:
        dump(neighbour, f, indent=4)

    send_msg(user=current_user, proto=3)

port=5005
print(accounts['ip'], port)
info = socket.getaddrinfo(accounts['ip'], port, socket.AF_INET6, socket.SOCK_STREAM,0, socket.AI_PASSIVE)
af, socktype, proto, canonname, sa = info[0]
sock = socket.socket(af, socktype, proto)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
sock.bind(sa)
sock.listen()

IP = exp_ipv6(accounts['ip'])
while True:
    sleep(0.1)
    conn, src = sock.accept()
    print(src[0])
    if exp_ipv6(src[0])!=IP:
        c=conn.recv(1)
        data = b''
        try:
            while c:
                data+= c
                c = conn.recv(1)
            data =struct.pack("I%ds" % (len(data),), len(data), data)
            with open('server_packet', 'ab') as f:
                f.write(data)
            with open ('server_packet_size', 'a+') as f:
                f.write("%d "%(len(data)))
            with open('server_packet_ip', 'ab') as f:
                f.write(bytes(ipv6_rmv_dots(exp_ipv6(src[0])), 'ascii'))
        except UnicodeDecodeError:
            pass
    conn.close()
    request_process()
