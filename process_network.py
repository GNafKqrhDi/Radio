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
                with open(fnames[i]+'_ip', 'r+b') as ip:
                    for size in data_size:
                        data = f.read(size)
                        if len(data)>0:
                            try:
                                timestamp = float()
                                if i==1:
                                    timestamp = float(data[0:25].decode())
                                else:
                                    timestamp = float(data[4:25+4].decode())
                                ls.append((timestamp, pos, size, i,toipv6(ip.read(32).decode())))
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
                process_server(data, current_user, accounts, neighbour, elem[4])
            else:
                process_multicast(data, current_user, accounts, elem[4])
        for i in range(2):
            with open(fnames[i], 'wb+') as f:
                f.write(b'')
            with open(fnames[i]+'_size', 'w') as f:
                f.write('')
            with open(fnames[i]+'_ip', 'wb+') as f:
                f.write(b'')
