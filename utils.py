
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


import libtorrent as lt
from hashlib import sha512, sha1
from random import randint as ri
from os import popen, path
from json import load, dump
from time import time, sleep
from numpy.random import permutation as perm
import numpy as np
import netifaces, socket, struct, tarfile, sys
from cryptography.fernet import Fernet

port = 5005
port_multi = 5000
CHARACTERS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
HEX = "0123456789abcdef"
#user+hsh+multicast+"0.500000"+user_hsh+'0'+tracker_ip
user_hash_ip = 25+128+32+8+128+1+32#maximum size of username + 128 of hash of user on the network
                        # + 32 characters for multicast address + 8 characters to define his probability of sending right file
                        # 128 characters of his hash on his own network + 1 character to tell if he's has been blocked
                        # +32 characters of "tracker-like" server
BLOCK_SIZE = 1000
blocked_words = ['time', 'ip', 'tracker_ip']

crypto_key = b'HZWAkxWXSV-38g5QdjJePSwWO9f43RYDuYP-uvARtDM='
#key = Fernet.generate_key()
crypto_algo = Fernet(crypto_key) # use any algorithm that suits you

def random_str(n):
    return ''.join([CHARACTERS[ri(0, len(CHARACTERS)-1)] for i in range(n)])

def proof_of_work(n):
    flag=False
    s=""
    while not flag:
        s=random_str(n).encode()
        hsh = sha512(s).hexdigest()
        flag=True
        for j in range(3):
            if hsh[j]!='0':
                flag=False
    return s.decode()
def check_POW(s):
    hsh = sha512(bytes(s, 'ascii')).hexdigest()
    flag=True
    for j in range(3):
        if hsh[j]!='0':
            flag = False
    return flag
def read(fname):
    f=open(fname, 'r')
    s=f.read()
    f.close()
    return s
def write(fname, s):
    f=open(fname, 'w+')
    f.write(s)
    f.close()
def gen_key(n, key_file):
#   creates a key of "n" characters that is saved to a file, with
#    filename key_file and returns the hash of the key
    s=random_str(n)
    hsh = sha512(bytes(s, 'ascii')).hexdigest()
    f=open(key_file, 'w+')
    f.write(s)
    f.close()
    return hsh
def cmp(s1, s2):
#   This function works the same way as the c++ strcmp function
    if s1==s2:
        return 0
    else:
        if s1>s2:
            return 1
        else:
            return -1
def writeb(x, fname, pos):
#    write a string "x" to binary file "fname" at position "pos"
    with open(fname, 'r+b') as f:
        f.seek(pos)
        f.write(x)
def readb(fname, pos, n):
#    reads first "n" bytes of binary file with filename "fname" at position "pos"
    with open(fname, 'r+b') as f:
        f.seek(pos)
        return f.read(n)
def search(key, fname, n, insert=True, update=False):
#    Given a key, this function searches on a binary tree structured file that contain
#    a list of strings, if there is a string such that the first "n" characters match
#    the first "n" characters of the key. If "update" is true and it matches, then the string
#    on the binary file will be replaced by the key. If it does not match any string and insert
#    is true, it will append the new string to the file in a way that preserves the binary tree
#    structure
    N = len(key)
    m=int()
    s=key[0:n]
    try:
        with open(fname+'_input', 'r') as f2:
            m=int(f2.read())
    except FileNotFoundError:
        return [False, str()]
    pos=0
    while (pos<m):
        aux = readb(fname, pos, n)
        x=cmp(aux, s)
        if (x==0):
            if update:
                writeb(key, fname, pos)
                return [True, str()]
            else:
                return [True, readb(fname, pos, N).decode()]
        else:
            pos = readb(fname, pos+N, 12) if x>0 else readb(fname, pos+N+12, 12)
            pos = int(pos) if pos!=b'' else 0
            if pos==0:
                if insert:
                    mx = BLOCK_SIZE
                    i=0
                    while (1<<i)*BLOCK_SIZE<=m: i+=1
                    #1<<i*BLOCK_SIZE>m >= 1<<(i-1)*BLOCK_SIZE
                    if m+N>=(1<<i)*BLOCK_SIZE:
                        with open(fname+'_tmp', 'wb+') as f:
                            SIZE = (1<<(i+1))*BLOCK_SIZE
                            for i in range(SIZE):
                                f.write(b'0')
                        with open(fname,'rb') as orig:
                            with open(fname+'_tmp', 'r+b') as f:
                                c=orig.read()
                                while c:
                                    f.write(c)
                                    c=orig.read()
                        with open(fname, 'r+b') as orig:
                            with open(fname+'_tmp', 'r+b') as f:
                                c=f.read()
                                while c:
                                    orig.write(c)
                                    c=f.read()
                        popen("""echo "1" > %s_tmp"""%(fname))

                    writeb(bytes("%012d"%(m), 'ascii'), fname, pos+N+(0 if x>0 else 12))
                pos=m
    if insert:
        writeb(key, fname, m)
        with open(fname+'_input', 'w') as f2:
            f2.write(str(m+N+24))
    return [False, str()]
def check_username(s):
#   Check if the username is valid
    return 10<len(s) and len(s)<=25
def exp_ipv6(s):
#   receives an ipv6 (variable "s") and returns the same ipv6 but showing all the zeros
#       the function exp(ands) ipv6
    if '::' in s:
        s=s.split("::")
        x=s[0].split(':')
        y=s[1].split(':')
        s=x+["0000"]*(8-len(x)-len(y))+y
        return ':'.join(['0'*(4-len(e))+e for e in s])
    else:
        return ':'.join(['0'*(4-len(e))+e for e in s.split(':')])
def toipv6(s):
#   converts a string of 32 characters to a ipv6 address, that may or may not exist
    return ':'.join([s[i:4+i] for i in range(0, len(s), 4)])
def ipv6_rmv_dots(s):
#   removes the 2 dots of an ipv6 address
    return exp_ipv6(s).replace(':', '')
def random_multicast():
    return 'ff0e:'+':'.join([''.join([HEX[ri(0, 15)] for i in range(4)]) for j in range(7)])
def dfs(ls, dc, n=0, path=""):
    for k in dc:
        ls.append([k, dc[k]['comment'], n, path+'-'+k])
        dfs(ls, dc[k]['answear'], n+1, path+'-'+k)
def write_msg(txt, chat, path, user):#write_msg(request.args["new_text"], feed[key]['comment']
    dc=dict()
    with open(chat, 'r') as f:
        dc=load(f)
    path = path.split('-')
    if path[0]=='':
        path.pop(0)
    aux=dc
    for e in path:
        aux=aux[e]["answear"]
    aux[user] = {"comment":txt, "answear":{}}
    with open(chat, 'w+') as f:
        dump(dc, f, indent=4)
    ls=list()
    dfs(ls, dc)
    return ls
def create_link(user):
    aux, _,_, _, _ = read('users@'+user+'_input').split()
    sz=len(aux)+8
    ls = [b'1'*sz]
    with open('users@'+user, 'rb') as f:
        while ls[-1]!=b'\0'*sz:
            ls.append(f.read(sz))
    ls.pop(0)
    ls.pop(-1)
    ls = [(int(e[sz-8-32-18:sz-8-32-9]), int(e[sz-8-32-9:sz-8-32]), toipv6(e[sz-8-32:sz-8].decode())) for e in ls]
    ls = sorted(ls, key=lambda x:x[0]/x[1])
    ls = [e[2] for e in ls]
    ls = ls[0:100]
    return '//'.join(ls)
def get_random_ips(n, acc):
    N = 32+24
    END = int(read('ips@'+acc+'_input'))//N
    ls = perm(range(END))[0:n]
    try:
        return [toipv6(readb("ips@"+acc, pos*N, 32).decode()) for pos in ls]
    except FileNotFoundError:
        return list()
def is_network_small(acc):
    try:
        x = float(read("users@"+acc+'_input'))/(user_hash_ip+24)
        y = bool(int(read("has_accounts@%s"%(acc))))
        return y and (x<=5)
    except FileNotFoundError:
        return False
def estimate_probability(dc):
    A = 1
    B = 1
    for k in dc:
        for e in dc[k]:
            A*=e
            B*=1-e
    aux = dict()
    for k in dc:
        x = 1
        y = 1
        for e in dc[k]:
            x*=e
            y*=(1-e)
        aux[k] = x*x*B/(x*x*B+y*y*A)
    return aux
def process_server(data, current_user, accounts, neighbour):
    data_decoded = data.decode()
    key = data_decoded[32+25+0:32+25+128]
    hsh = data_decoded[32+25+128:32+25+256]
    user_hash = data_decoded[32+25+257:32+25+257+128]
    sz = int(data_decoded[32+25+257+128:32+25+261+128])
    user, acc= data_decoded[32+25+261+128:32+25+sz+261+128].split("@")#actually user and account   
    src = toipv6(data_decoded[0:32])
    if check_username(user) and check_username(acc):
        proto = int(data_decoded[32+25+256])
        network_small = is_network_small(acc)
        L = 25+sz+261+128+32
        if (accounts.get(acc, None)!=None):
            print(user, acc)
            user+='#'*(user_hash_ip-len(user))
            res = search(bytes(user, 'ascii'), "users@"+acc, 25, insert=False,update=False)
            user_blocked = (res[1][-1]=='1') if res[0] else True
            if (res[0] or network_small) and not user_blocked:
                res = res[1]
                hsh2 = sha512(bytes(key, "ascii")).hexdigest()
                user_authenticated = hsh2==res[25:25+128]
                print(user_authenticated)
                if user_authenticated or network_small:
                    search(bytes(user[0:25]+hsh+res[25+128:25+128+32+8]+user_hash+'0'+res[25+128+32+8+128+1:], 'ascii'), 'users@'+acc, 25, insert=False, update=True)
                    aux = search(bytes(user, 'ascii'), 'users@'+user.replace('#', ''), 25, insert=False, update=False)
                    if aux[0]:
                        search(bytes(user[0:25]+user_hash+aux[1][25+128:25+128+32+8]+user_hash+'0'+aux[1][25+128+32+8+128+1:], 'ascii'), 'users@'+user.replace("#", ''), 25, insert=False, update=True)
                    search(data[0:32],'ips@'+acc, 32, insert=True, update=False)
                    user = user.replace('#', '')
                    P = float(res[25+128+32:25+128+32+8]) #Using P?
                    if proto==3 or proto==8:
                        tt= float(data_decoded[L:])
                        send_msg(current_user, 5, msg=None, acc=acc, ipv6=src)
                        if neighbour.get(acc, None)==None:
                            neighbour[acc] = dict()
                            neighbour[acc]['addrs'] = list()
                            neighbour[acc]['count']='0'
                            nneighbour[acc]['login']='1'
                        if src not in neighbour[acc]['addrs']:
                            neighbour[acc]['addrs'].append(src)
                            neighbour[acc]['count']=int(neighbour[acc]['count'])+1
                            neighbour[acc][user]=dict()
                            neighbour[acc][user]['num']=neighbour[acc]['count']
                            neighbour[acc][user]['prob'] = P
                            neighbour[acc][user]['type'] = proto
                            with open('neighbour.json', 'w+') as f:
                                dump(neighbour, f, indent=4)
                            send_msg(user=user, proto=6, acc=acc, ipv6=src, time_of_request=tt)                    
                    if proto==5:
                        if neighbour.get(acc, None)!=None:
                           # neighbour[acc]['addrs'].append(src)
                            neighbour[acc]['count']=int(neighbour[acc]['count'])+1
                            neighbour[acc][user] = dict()
                            neighbour[acc][user]['num']=neighbour[acc]['count']
                            neighbour[acc][user]['prob'] = P
                            neighbour[acc]['login']=1
                            with open('neighbour.json', 'w+') as f:
                                dump(neighbour, f, indent=4)

                    if proto==6:
                        if neighbour.get(acc, None)!=None:
                            if neighbour[acc].get(user, None)!=None:
                                data_decoded = bytes(data_decoded[L:], 'ascii')
                                with open(str(neighbour[acc][user]['num'])+'@'+acc, 'ab+') as f:
                                    f.write(data_decoded)
                                with open(str(neighbour[acc][user]['num'])+'@'+acc+'_size', 'a+') as f:
                                    f.write("%d "%(len(data_decoded)))
def process_multicast(data, current_user, accounts):
    data_decoded = data.decode()
    proto = int(data_decoded[32+25+256])
    if len(data_decoded)<257:
        return ;
    if proto==1:#sign up
        work = data_decoded[32+25+0:32+25+128]
        if check_POW(work):
            sz = int(data_decoded[32+25+257+32:32+25+257+32+4])
            user,acc = data_decoded[32+25+257+32+4:32+25+257+32+4+sz].split('@')
            print(user)
            if check_username(user) and current_user==acc:
                network_small = is_network_small(acc)
                user += "#"*(25-len(user))
                res=search(bytes(work, 'ascii'), "keys@"+acc, 128, insert=True, update=False)
                print(res)
                print(network_small)
                if not res[0] or network_small:
                    with open('week_data@'+acc, 'ab') as f:
                        f.write(data)
                    with open('subs@'+acc, 'ab') as f:
                        f.write(data)
                    with open('week_data@'+acc+'_size', 'a') as f:
                        f.write("%d "%(len(data)))
                    with open('subs@'+acc+'_size', 'a') as f:
                        f.write("%d "%(len(data)))
                    search(data[0:32],'ips@'+acc, 32, insert=True, update=False)
                    hsh, multicast, user_hsh, tracker_ip= data_decoded[32+25+128:32+25+256], data_decoded[32+25+257:32+25+257+32], data_decoded[32+25+293+sz:32+25+293+sz+128],data_decoded[0:32]
                    search(bytes(user+hsh+multicast+"0.500000"+user_hsh+'0'+tracker_ip,'ascii'),"users@"+acc, 25,insert=True, update=False)
    else:
        key = data_decoded[32+25:32+25+128]
        hsh = data_decoded[32+25+128:32+25+256]
        sz = int(data_decoded[32+25+257:32+25+261])
        user, acc= data_decoded[32+25+261:32+25+sz+261].split("@")#actually user and account
        if check_username(user) and check_username(acc):
            network_small = is_network_small(acc)
            is_page_owner = (user==acc)
            L=sz+261+25+32
            if (accounts.get(acc, None)!=None):
                print(user, acc)
                user+='#'*(user_hash_ip-len(user))
                res = search(bytes(user, 'ascii'), "users@"+acc, 25, insert=False,update=False)
                user_blocked = (res[1][-1]=='1') if res[0] else True
                if (res[0] or network_small) and not user_blocked:
                    res = res[1]
                    hsh2 = sha512(bytes(key, "ascii")).hexdigest()
                    user_authenticated = hsh2==res[25:25+128]
                    print(user_authenticated)
                    if user_authenticated or network_small:
                        with open('week_data@'+acc, 'ab') as f:
                            f.write(data)
                        with open('week_data@'+acc+'_size', 'a') as f:
                            f.write("%d "%(len(data)))
                        search(data[0:32],'ips@'+acc, 32, insert=True, update=False)

                        if proto==4 or proto==7 or proto==9:
                            if not is_page_owner:
                                search(bytes(user[0:25]+hsh+res[25+128:user_hash_ip], 'ascii'),"users@"+acc, 25, insert=False, update=True)
                            else:
                                search(bytes(user[0:25]+hsh+res[25+128:25+128+32+8]+hsh+'0'+res[25+128+32+8+1+128:], 'ascii'), "users@"+acc, 25, insert=False, update=True)
                        if proto==4 and is_page_owner:
                            titlesz = int(data_decoded[L:L+4])
                            title = data_decoded[L+4:L+4+titlesz].replace(user+'_folder/', '')
                            linksz = int(data_decoded[L+4+titlesz:L+8+titlesz])
                            link = data_decoded[L+8+titlesz:L+8+titlesz+linksz]#instead of file, now is download link
                            content = data_decoded[L+8+titlesz+linksz:len(data_decoded)]
                            files = dict()
                            ftype = str() if '.' not in title else title.split('.')[-1]
                            new_hash = sha1(bytes(title+content, "ascii")).hexdigest()#change to sha1
                            with open(acc+'_folder/'+new_hash+"@comment", 'w+') as f:
                                dump(dict(), f)
                            with open('feed.json', 'r') as f:
                                feed = load(f)
                            if feed.get(current_user, None)==None:
                                feed[current_user]=dict()
                            aux = dict()
                            aux[new_hash]=dict()
                            aux[new_hash]["title"]=title
                            aux[new_hash]["content"]=content
                            aux[new_hash]["file"]="" #no file until Downloaded
                            aux[new_hash]["comment"]=acc+'_folder/'+new_hash+"@comment"
                            aux[new_hash]["account"]=acc
                            aux[new_hash]["time"] = time()
                            aux[new_hash]["link"] = link
                            aux[new_hash]["downloaded"] = 0
                            aux[new_hash]['compressed_file'] = ''
                            aux.update(feed[current_user])
                            feed[current_user] = aux
                            with open('feed.json', 'w+') as f:
                                dump(feed, f, indent=4)
                        if proto==7:
                            feed = dict()
                            data_decoded = data_decoded[L:]
                            with open('feed.json', 'r') as f:
                                feed = load(f)
                            path_len = int(data_decoded[0:4])
                            P = data_decoded[4:4+path_len]
                            key, path = P.split('@')
                            txt_len = int(data_decoded[4+path_len:4+path_len+4])
                            txt = data_decoded[8+path_len:8+path_len+txt_len]
                            write_msg(txt, feed[current_user][key]['comment'], path, user.replace('#', ''))
#                       user_hash_ip = 25+128+32+8+128+1+32
                        if proto==9 and is_page_owner:
                            block = data_decoded[L:]
                            search(bytes(block+'#'*(25+128+32+8+128-len(block))+'1'+'0'*32, 'ascii'), 'users@'+acc, 25, insert=False, update=True)
                        if proto==2:
                            new_key = data_decoded[L:L+128]
                            aux = search(bytes(user, 'ascii'), 'users@'+user.replace('#', ''), 25, insert=False, update=False)
                            if aux[0]:
                                search(bytes(user[0:25]+new_key+aux[1][25+128:25+128+32+8]+new_key+'0'+aux[1][25+128+32+8+128+1:], 'ascii'), 'users@'+user.replace('#', ''), 25, insert=False, update=True)
                            search(bytes(user[0:25]+hsh+res[25+128:25+128+32+8]+new_key+'0'+res[25+128+32+8+128+1:], 'ascii'), 'users@'+acc, 25, insert=False, update=True)
def server_socket(sockip=str()):
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    sock.bind((sockip, ri(6000, 10000)))
    return sock
def multicast_socket(sockip=str()):
    ifn = str()
    with open("current_dev_name",'r') as f:
        ifn = f.read().replace('\n', '')
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    ifi = socket.if_nametoindex(ifn)
    ifis = struct.pack("I", ifi)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, ifis)
    ttl = struct.pack('i', 5)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, ttl)
    sock.bind((sockip, ri(6000, 10000)))
    return sock
def send_msg(user, proto, msg=None, acc=None, accounts=dict(), \
        ipv6=str(), content=str(), time_of_request=None, title=str(), link=str()):
    accounts, sockip, timestamp, current_user = dict(), str(), "%025f"%(time()), str()
    with open('current_user', 'r') as f:
        current_user = f.read().replace('\n', '')
    if current_user=='None': return ;

    res = search(bytes(current_user+'#'*(user_hash_ip-len(current_user)), 'ascii'), "users@"+current_user, 25, insert=False,update=False)
    user_hash= res[1][25:25+128]
    if accounts==dict():
        with open('accounts.json') as f:
            accounts=load(f)
    accounts = accounts[current_user]
    sockip=accounts['ip'] if accounts['ip']!='None' else get_ip()
    if proto==1:
        sock = multicast_socket(sockip)
        sock_addr = socket.getaddrinfo(accounts[acc], port_multi, socket.AF_INET6, socket.SOCK_DGRAM)[0][4]
        work = proof_of_work(128)
        hsh = gen_key(128, acc)
        user_account=current_user+'@'+acc
#        res = search(bytes(current_user+'#'*(user_hash_ip-len(current_user)), 'ascii'), 'users@'+current_user, 25, insert=False, update=False)
        search(bytes(current_user+'#'*(25-len(current_user))+hsh+res[1][25+128:], 'ascii'), 'users@'+acc, 25, insert=True, update=True)

        safe_msg = accounts['tracker_ip']+ timestamp+work+hsh+'1'+ipv6_rmv_dots(accounts[current_user])+"%04d"%(len(user_account))+user_account+user_hash
        sock.sendto(crypto_algo.encrypt(bytes(safe_msg, "ascii")), sock_addr)
        sock.close()
    if proto==3 or proto==5 or proto==6:
        key_hash, neighbour=dict(), dict()
        flag = True
        if proto==3 or current_user==acc:
            with open('neighbour.json', 'r') as f:
                neighbour= load(f)
            for aux_acc in accounts:
                if aux_acc not in blocked_words and (proto!=3 or (proto==3 and not bool(int(neighbour[aux_acc]['login'])))):
                    key = read(aux_acc).replace('\n','')
                    hsh = gen_key(128, aux_acc)
                    key_hash[aux_acc] = (key, hsh)
                    if aux_acc==current_user:
                        user_hash = hsh
        else:
            key = read(acc).replace('\n', '')
            hsh = gen_key(128, acc)
            key_hash[acc] = (key, hsh)

        if proto==3:
            for aux_acc in key_hash:
                proto = '3' if bool(int(read("has_accounts@"+aux_acc))) else '8'
                for addr in neighbour[aux_acc]['addrs']:
                    timestamp = "%025f"%(time())
                    neighbour[aux_acc]['type'] = proto
                    user_account = user+'@'+aux_acc

                    safe_msg = accounts['tracker_ip']+ timestamp+key_hash[aux_acc][0]+key_hash[aux_acc][1]+proto+user_hash+"%04d"%(len(user_account))+user_account+"%s"%(str(accounts['time']))
                    sock = server_socket(sockip)
                    sock.connect((addr, port))
                    sock.send(crypto_algo.encrypt(bytes(safe_msg, "ascii")))
                    sock.close()
        if proto==5:
            sock = server_socket(sockip)
            try:
                timestamp = "%025f"%(time())
                proto = str(proto)
                user_account = current_user+'@'+acc
                safe_msg = accounts['tracker_ip']+ timestamp+key_hash[acc][0]+key_hash[acc][1]+proto+user_hash+"%04d"%(len(user_account))+user_account
                sock.connect((ipv6, port))
                sock.send(crypto_algo.encrypt(bytes(safe_msg, 'ascii')))
                sock.close()
            except OSError:
                pass
        if proto==6:
            if time_of_request!=None:
                sock = server_socket(sockip)
                fname = ('week_data@'+acc) if neighbour[acc][user]['type']=='3' else 'subs@'+acc
                time_of_request = time_of_request if neighbour[acc][user]['type']=='3' else 0
                
                timestamp = "%025f"%(time())
                proto = str(proto)
                user_account = current_user+'@'+acc
                safe_msg = bytes(accounts['tracker_ip']+timestamp+key_hash[acc][0]+key_hash[acc][1]+proto+user_hash+"%04d"%(len(user_account))+user_account,'ascii')
                sock.connect((ipv6, port))
                sizes = list()
                with open(fname+'_size', 'r') as f:
                    sizes = list(map(int, f.read().split()))
#TODO a more memory efficient version of this protocol, that sends packet by packet
                for size in sizes:
                    with open(fname, 'rb') as f:
                        data = f.read(size)
                        T= float(data[32:32+25].decode())
                        if T>time_of_request:
                            if neighbour[acc][user]['type']=='8':
                                data = data.decode()
                                aux_user_size = int(data[32+25+128+128+1+32:32+25+128+128+1+32+4])
                                aux_user = data[32+25+128+128+1+32+4:32+25+128+128+1+32+4+aux_user_size]
                                aux_user+='#'*(user_hash_ip-aux_user_size)
                                res = search(bytes(aux_user, 'ascii'), 'users@'+acc, 25, insert=False, update=False)
                                if res[0]: data = data[32+0:32+25+128]+res[1][25:25+128]+data[32+25+128+128:]
                            safe_msg+=data
                sock.send(crypto_algo.encrypt(safe_msg))
                sock.close()
        #sleep(0.1)
        sock2 = multicast_socket(sockip) 
        for aux_acc in key_hash:
            if aux_acc not in blocked_words:
                timestamp = "%025f"%(time())
                sock_addr = socket.getaddrinfo(accounts[aux_acc], port_multi, socket.AF_INET6, socket.SOCK_DGRAM)[0][4]
                user_aux_account = current_user+'@'+aux_acc
                sock2.sendto(crypto_algo.encrypt(bytes(accounts['tracker_ip']+timestamp+key_hash[aux_acc][0]+key_hash[aux_acc][1]+'2'+"%04d"%(len(user_aux_account))+user_aux_account+user_hash,"ascii")), sock_addr)
        sock2.close()
    if proto==4 or proto==7 or proto==9:
        key = read(acc).replace('\n','')
        hsh = gen_key(128, acc)
        if current_user == acc:
            user_hash = hsh
        sock= multicast_socket(sockip)
        sock_addr = socket.getaddrinfo(accounts[acc], port_multi, socket.AF_INET6, socket.SOCK_DGRAM)[0][4]
        user_account = user+'@'+acc
        if proto==4:
            safe_msg = accounts['tracker_ip']+ timestamp+key+hsh+str(proto)+"%04d"%(len(user_account))+user_account+\
            "%04d"%(len(title))+title+"%04d"%(len(link))+link+content
            if user==acc:
                sock.sendto(crypto_algo.encrypt(bytes(safe_msg, "ascii")), sock_addr)
        else:
            safe_msg = accounts['tracker_ip']+ timestamp+key+hsh+str(proto)+"%04d"%(len(user_account))+user_account+msg
            sock.sendto(crypto_algo.encrypt(bytes(safe_msg, "ascii")), sock_addr)
        if user==acc:
            for elem in accounts:
                if elem not in blocked_words and elem!=acc:
                    user_account = current_user+"@"+elem
                    key = read(elem).replace('\n','')
                    hsh = gen_key(128, elem)
                    timestamp = "%025f"%(time())
                    safe_msg = accounts['tracker_ip']+ timestamp+key+hsh+'2'
                    safe_msg+="%04d"%(len(user_account))+user_account+user_hash
                    addr=accounts[elem]
                    sock_addr = socket.getaddrinfo(addr, port_multi, socket.AF_INET6, socket.SOCK_DGRAM)[0][4]
                    sock.sendto(crypto_algo.encrypt(bytes(safe_msg, "ascii")), sock_addr)
        sock.close()
def request_process():
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)

            sock.connect(("::1", 2222))
            sock.send(b'1')
            sock.close()
        except OSError:
            pass
def interface_names():
    ifs= popen("nmcli con show --active").read().split('\n')
    ifs.pop(0)
    ifs.pop(-1)
    ifs = [list(map(str, e.split())) for e in ifs]
    devs = [e[-1] for e in ifs]
    ifs = [e[0:len(e)-3] for e in ifs]
    ifs = [' '.join(e) for e in ifs]
    ifs = {ifs[i]:devs[i] for i in range(len(ifs))}
    return ifs
def interface_ips():
    ifs = interface_names()
    res = {k: [e for e in popen("ip addr show dev %s"%(ifs[k])).read().split('\n') if "inet6" in e] for k in ifs}
    return {k:(res[k] if res[k]!=list() else [None]) for k in res}
def upload_torrent(fname):
    fs = lt.file_storage()
    lt.add_files(fs, fname)
    t=lt.create_torrent(fs)
    with open("trackers", 'r') as f:
        s=f.readline()
        while s:
            t.add_tracker(s.replace('\n', ''))
            s=f.readline()
    t.set_creator(fname)
    lt.set_piece_hashes(t, './')
    torrent = t.generate()
    with open(fname+'.torrent', 'wb') as f:
        f.write(lt.bencode(torrent))
    ses=lt.session()
    ses.listen_on(6881, 6891)
    handle = ses.add_torrent({'ti': lt.torrent_info(torrent), 'save_path': "./"})
    link = lt.make_magnet_uri(lt.torrent_info(torrent))
    s = handle.status()
    while s.progress<1:
        s = handle.status()
        state_str = ['queued', 'checking', 'downloading metadata', \
          'downloading', 'finished', 'seeding', 'allocating', 'checking fastresume']

        print('\r%.2f%% complete (down: %.1f kb/s up: %.1f kB/s peers: %d) %s' % \
          (s.progress * 100, s.download_rate / 1000, s.upload_rate / 1000, s.num_peers, state_str[s.state]))
        sys.stdout.flush()
        sleep(0.1)
    return link
def magnet_to_torrent(magnet_uri):
    """
    Args:
        magnet_uri (str): magnet link to convert to torrent file
        dst (str): path to the destination folder where the torrent will be saved
    """
    # Parse magnet URI parameters
    params = lt.parse_magnet_uri(magnet_uri)

    # Download torrent info
    session = lt.session()
    handle = session.add_torrent(params)
    while not handle.has_metadata():
        sleep(0.1)

    # Create torrent and save to file
    torrent_info = handle.get_torrent_info()
    torrent_file = lt.create_torrent(torrent_info)
    torrent_name = torrent_info.name() + ".torrent"
    with open(torrent_name, "wb") as f:
        f.write(lt.bencode(torrent_file.generate()))
    return torrent_name
def make_tarfile(output_filename, source_dir):
    with tarfile.open(output_filename, "w:gz") as tar:
        tar.add(source_dir, arcname=path.basename(source_dir))
def decompress(fname, path):
    with tarfile.open(fname, "r:gz") as tar:
        if len(tar.getmembers())>1:
            popen("mkdir %s/%s_folder"%(path, fname))
            tar.extractall(path="mkdir %s/%s_folder"%(path, fname))
            return [True, "%s/%s_folder"%(path, fname)]
        else:
            tar.extractall(path=path)
            members = tar.getmembers()
            return [members[0].isdir(),path+'/'+members[0].get_info()['name']]
def kill_server():
    request = b"GET /kill HTTP/1.1\nHost: 127.0.0.1:5000\n\n"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 5000))
    s.send(request)
    s.close()
def get_ip():
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.connect(('aa::', 1))
    return exp_ipv6(s.getsockname()[0])#cannot remove the dots due to send_msg function
