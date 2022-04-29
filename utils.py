from hashlib import sha512
from random import randint as ri
from os import popen
from json import load, dump
from time import time, sleep
from numpy.random import permutation as perm
import netifaces
import socket
import struct
CHARACTERS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
HEX = "0123456789abcdef"
user_hash_ip = 25+128+32+8+128+1 #maximum size of username + 128 of hash of user on the network
                        # + 32 characters for ipv6 + 8 characters to define his probability of sending right file
                        # 128 characters of his hash on his own network + 1 character to tell if he's has been blocked
BLOCK_SIZE = 1000

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
    hsh = sha512(bytes(s, 'UTF-8')).hexdigest()
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
    s=random_str(n)
    hsh = sha512(bytes(s, 'UTF-8')).hexdigest()
    f=open(key_file, 'w+')
    f.write(s)
    f.close()
    return hsh
def cmp(s1, s2):
    if s1==s2:
        return 0
    else:
        if s1>s2:
            return 1
        else:
            return -1
def writeb(x, fname, pos):
    with open(fname, 'r+b') as f:
        f.seek(pos)
        f.write(x)
def readb(fname, pos, n):
    with open(fname, 'r+b') as f:
        f.seek(pos)
        return f.read(n)
def search(key, fname, n, insert=True, update=False):
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
            if x>0:
                pos = readb(fname, pos+N, 12)
            else:
                pos = readb(fname, pos+N+12, 12)
            pos = int(pos) if pos!=b'' else 0
            if pos==0:
                if insert:
                    mx = BLOCK_SIZE
                    i=0
                    while (1<<i)*BLOCK_SIZE<=m:
                        i+=1
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
    return 10<len(s) and len(s)<=25
def exp_ipv6(s):
    if '::' in s:
        s=s.split("::")
        x=s[0].split(':')
        y=s[1].split(':')
        s=x+["0000"]*(8-len(x)-len(y))+y
        return ':'.join(['0'*(4-len(e))+e for e in s])
    else:
        return ':'.join(['0'*(4-len(e))+e for e in s.split(':')])
def toipv6(s):
    return ':'.join([s[i:4+i] for i in range(0, len(s), 4)])
def ipv6_rmv_dots(s):
    return exp_ipv6(s).replace(':', '')#TODO function to check if the ipv6 sent at server is valid
def random_ipv6(iff="wlp2s0"):
    prefix = popen("ip addr show dev %s | grep -i global | grep -i inet6"%(iff)).read().split('\n')
    prefix = [e for e in prefix if "failed" not in e and e!='' and "mngtmpaddr" not in e]
    prefix = ':'.join(prefix[0].split()[1].split(':')[0:4])
    return prefix+':'+':'.join([''.join([HEX[ri(0, 15)] for i in range(4)]) for j in range(4)])
def random_multicast():
    return 'ff0e:'+':'.join([''.join([HEX[ri(0, 15)] for i in range(4)]) for j in range(7)])
def hash_key(fname):
    return sha512(bytes(read(fname), 'UTF-8')).hexdigest()
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
def get_pass(acc):
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
def process_server(data, current_user, accounts, neighbour, src):
    data = data[4:]
    key = data[25+0:25+128].decode()
    hsh = data[25+128:25+256].decode()
    user_hash = data[25+257:25+257+128].decode()
    sz = int(data[25+257+128:25+261+128].decode())
    user, acc= data[25+261+128:25+sz+261+128].decode().split("@")#actually user and account
    if check_username(user) and check_username(acc):
        proto = int(data[25+256:25+257].decode())
        PASS = get_pass(acc)
        L = 25+sz+261+128
        if (accounts.get(acc, None)!=None):
            print(user, acc)
            user+='#'*(user_hash_ip-len(user))
            res = search(bytes(user, 'ascii'), "users@"+acc, 25, insert=False,update=False)
            BLOCKED = (res[1][-1]=='1') if res[0] else True
            if (res[0] or PASS) and not BLOCKED:
                res = res[1]
                hsh2 = sha512(bytes(key, "UTF-8")).hexdigest()
                SUCCESS = hsh2==res[25:25+128]
                print(SUCCESS)
                if SUCCESS or PASS:
                    search(bytes(user[0:25]+hsh+res[25+128:25+128+32+8]+user_hash+'0', 'ascii'), 'users@'+acc, 25, insert=False, update=True)
                    aux = search(bytes(user, 'ascii'), 'users@'+user.replace('#', ''), 25, insert=False, update=False)
                    if aux[0]:
                        search(bytes(user[0:25]+user_hash+aux[1][25+128:25+128+32+8]+user_hash+'0', 'ascii'), 'users@'+user.replace("#", ''), 25, insert=False, update=True)
                    if src!=None:
                            search(bytes(ipv6_rmv_dots(src), 'ascii'),'ips@'+acc, 32, insert=True, update=False)
                            
                    user = user.replace('#', '')
                    P = float(res[25+128+32:25+128+32+8])
                    if proto==3 or proto==8:
                        tt= float(data[L:].decode())
                        send_msg(current_user, 5, msg=None, acc=acc, ipv6=src)
                        neighbour = dict()
                        if neighbour.get(acc, None)==None:
                            neighbour[acc] = dict()
                            neighbour[acc]['addrs'] = list()
                            neighbour[acc]['count']='0'
                        if src not in neighbour[acc]['addrs']:
                            neighbour[acc]['addrs'].append(src)
                            neighbour[acc]['count']=int(neighbour[acc]['count'])+1
                            neighbour[acc][user]=dict()
                            neighbour[acc][user]['num']=neighbour[acc]['count']
                            neighbour[acc][user]['prob'] = P
                            neighbour[acc][user]['type'] = proto
                            with open('neighbour.json', 'w+') as f:
                                dump(neighbour, f, indent=4)
                            send_msg(user=user, protocol=6, acc=acc, ipv6=src, time_of_request=tt)                    
                    if proto==5:
                        if neighbour.get(acc, None)!=None:
                           # neighbour[acc]['addrs'].append(src)
                            neighbour[acc]['count']=int(neighbour[acc]['count'])+1
                            neighbour[acc][user] = dict()
                            neighbour[acc][user]['num']=neighbour[acc]['count']
                            neighbour[acc][user]['prob'] = P
                            with open('neighbour.json', 'w+') as f:
                                dump(neighbour, f, indent=4)

                    if proto==6:
                        if neighbour.get(acc, None)!=None:
                            if neighbour[acc].get(user, None)!=None:
                                data = data[L:]
                                with open(str(neighbour[acc][user]['num'])+'@'+acc, 'ab+') as f:
                                    f.write(data)
                                with open(str(neighbour[acc][user]['num'])+'@'+acc+'_size', 'a+') as f:
                                    f.write("%d "%(len(data)))
def process_multicast(data, current_user, accounts, src=None):
    proto = int(data[25+256:25+257].decode())
    if len(data)<257:
        return ;
    if proto==1:#sign up
        work = data[25+0:25+128].decode()
        if check_POW(work):
            try:
                sz = int(data[25+257+32:25+257+32+4].decode())
            except ValueError:
                return ;
            user,acc = data[25+293:25+293+sz].decode().split('@')
            print(user)
            if check_username(user) and check_username(acc) and accounts.get(acc, None)!=None:
                PASS = get_pass(acc)
                user += "#"*(25-len(user))
                res=search(bytes(work, 'ascii'), "keys@"+acc, 128, insert=True, update=False)
                if not res[0] or PASS:
                    with open('week_data@'+acc, 'ab') as f:
                        f.write(data)
                    with open('subs@'+acc, 'ab') as f:
                        f.write(data)
                    with open('week_data@'+acc+'_size', 'a') as f:
                        f.write("%d "%(len(data)))
                    with open('subs@'+acc+'_size', 'a') as f:
                        f.write("%d "%(len(data)))
                    if src!=None:
                        search(bytes(ipv6_rmv_dots(src), 'ascii'),'ips@'+acc, 32, insert=True, update=False)
                    hsh = data[25+128:25+256].decode()
                    multicast = data[25+257:25+257+32].decode()
                    search(bytes(user[0:25]+hsh+multicast+"0.500000"+data[25+293+sz:len(data)].decode()+'0', 'ascii'),"users@"+acc, 25,insert=True, update=False)
    else:
        key = data[25:25+128].decode()
        hsh = data[25+128:25+256].decode()
        try:
            sz = int(data[25+257:25+261].decode())
        except ValueError:
            return ;
        user, acc= data[25+261:25+sz+261].decode().split("@")#actually user and account
        if check_username(user) and check_username(acc):
            PASS = get_pass(acc)
            flag = (user==acc)
            L=sz+261+25
            if (accounts.get(acc, None)!=None):
                print(user, acc)
                user+='#'*(user_hash_ip-len(user))
                res = search(bytes(user, 'ascii'), "users@"+acc, 25, insert=False,update=False)
                BLOCKED = (res[1][-1]=='1') if res[0] else True
                if (res[0] or PASS) and not BLOCKED:
                    res = res[1]
                    hsh2 = sha512(bytes(key, "UTF-8")).hexdigest()
                    SUCCESS = hsh2==res[25:25+128]
                    print(SUCCESS)
                    if SUCCESS or PASS:
                        with open('week_data@'+acc, 'ab') as f:
                            f.write(data)
                        with open('week_data@'+acc+'_size', 'a') as f:
                            f.write("%d "%(len(data)))
                        if src!=None:
                            search(bytes(ipv6_rmv_dots(src), 'ascii'),'ips@'+acc, 32, insert=True, update=False)
                        if proto==4 or proto==7 or proto==9:
                            if not flag:
                                search(bytes(user[0:25]+hsh+res[25+128:user_hash_ip], 'ascii'),"users@"+acc, 25, insert=False, update=True)
                            else:
                                search(bytes(user[0:25]+hsh+res[25+128:25+128+32+8]+hsh+'0', 'ascii'), "users@"+acc, 25, insert=False, update=True)
                        if proto==4 and flag:
                            fnamesz = int(data[L:L+4].decode())
                            fname = data[L+4:L+4+fnamesz].decode().replace(user+'_folder/', '')
                            ffsz = int(data[L+4+fnamesz:L+16+fnamesz].decode())#4+12=16
                            ff = data[L+16+fnamesz:L+16+fnamesz+ffsz]
                            content = data[L+16+fnamesz+ffsz:len(data)]
                            files = dict()
                            ftype = str() if '.' not in fname else fname.split('.')[-1]
                            new_hash = sha512(ff+content).hexdigest()
                            with open(acc+'_folder/'+new_hash+'.'+ftype, 'wb+') as f:
                                f.write(ff)
                            with open(acc+'_folder/'+new_hash+"@comment", 'w+') as f:
                                dump(dict(), f)
                            with open('feed.json', 'r') as f:
                                feed = load(f)
                            if feed.get(current_user, None)==None:
                                feed[current_user]=dict()
                            aux = dict()
                            aux[new_hash]=dict()
                            aux[new_hash]["title"]=fname
                            aux[new_hash]["content"]=content.decode()
                            aux[new_hash]["file"]=acc+'_folder/'+new_hash+'.'+ftype
                            aux[new_hash]["comment"]=acc+'_folder/'+new_hash+"@comment"
                            aux[new_hash]["account"]=acc
                            aux[new_hash]["time"] = time()
                            aux.update(feed[current_user])
                            feed[current_user] = aux
                            with open('feed.json', 'w+') as f:
                                dump(feed, f, indent=4)
                        if proto==7:
                            feed = dict()
                            data = data[L:].decode()
                            with open('feed.json', 'r') as f:
                                feed = load(f)
                            path_len = int(data[0:4])
                            P = data[4:4+path_len]
                            key, path = P.split('@')
                            txt_len = int(data[4+path_len:4+path_len+4])
                            txt = data[8+path_len:8+path_len+txt_len]
                            write_msg(txt, feed[current_user][key]['comment'], path, user.replace('#', ''))
                        if proto==9 and flag:
                            block = data[L:].decode()
                            search(bytes(block+'#'*(user_hash_ip-len(block)-1)+'1', 'ascii'), 'users@'+acc, 25, insert=False, update=True)
                        if proto==2:
                            new_key = data[L:L+128].decode()
                            aux = search(bytes(user, 'ascii'), 'users@'+user.replace('#', ''), 25, insert=False, update=False)
                            if aux[0]:
                                search(bytes(user[0:25]+new_key+aux[1][25+128:25+128+32+8]+new_key+'0', 'ascii'), 'users@'+user.replace('#', ''), 25, insert=False, update=True)
                            search(bytes(user[0:25]+hsh+res[25+128:25+128+32+8]+new_key+'0', 'ascii'), 'users@'+acc, 25, insert=False, update=True)
def send_msg(user, protocol, msg=None, acc=None, accounts=dict(), ipv6=str(), content=str(), time_of_request=None):
    sleep(0.1)
    user_hash_ip = 25+128+32+8+128+1
    port = 5005
    port_multi = 5000
    sockip=str()
    sockport=ri(6000, 10000)
    accounts = dict()
    timestamp = "%025f"%(time())
    current_user = str()
    with open('current_user', 'r') as f:
        current_user = f.read().replace('\n', '')
    ifn = str()
    with open("current_dev_name",'r') as f:
        ifn = f.read().replace('\n', '')
    res = search(bytes(current_user+'#'*(user_hash_ip-len(current_user)), 'ascii'), "users@"+current_user, 25, insert=False,update=False)
    user_hash= res[1][25:25+128]
    if accounts==dict():
        with open('accounts.json') as f:
            accounts=load(f)
            sockip=accounts[current_user]['ip'] if accounts[current_user]['ip']!='None' else str()
        if accounts.get(current_user, None)==None:
            exit()
        else:
            accounts= accounts[current_user]
    if protocol==1:
        addr=str()
        if ipv6==str():
            addr=accounts[acc]['multicast']
        else:
            addr=ipv6
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

        ifi = socket.if_nametoindex(ifn)
        ifis = struct.pack("I", ifi)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, ifis)
        sock_addr = socket.getaddrinfo(addr, port_multi, socket.AF_INET6, socket.SOCK_DGRAM)[0][4]
        ttl = struct.pack('i', 5)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, ttl)

        if sockip!=str():
            sock.bind((sockip, sockport))
        
        work = proof_of_work(128)
        hsh = gen_key(128, acc)
        ua=bytes(current_user+'@'+acc, "UTF-8")
        res = search(bytes(current_user+'#'*(user_hash_ip-len(current_user)), 'ascii'), 'users@'+current_user, 25, insert=False, update=False)
        search(bytes(current_user+'#'*(25-len(current_user))+hsh+res[1][25+128:], 'ascii'), 'users@'+acc, 25, insert=True, update=True)
        
        safe = bytes(timestamp+work+hsh+'1'+ipv6_rmv_dots(accounts[current_user]['multicast']), "UTF-8")
        safe+=bytes("%04d"%(len(ua)), "UTF-8")
        safe+=ua
        safe+=bytes(user_hash, "UTF-8")

        sock.sendto(safe, sock_addr)
        sock.close()
    if protocol==3 or protocol==5 or protocol==6:
        akh=dict()
        if protocol==3 or current_user==acc:
            for elem in accounts:
                if elem!='time' and elem!='ip':
                    key = read(elem).replace('\n','')
                    hsh = gen_key(128, elem)
                    akh[elem] = (key, hsh)
                    if elem==current_user:
                        user_hash = hsh
        else:
            key = read(acc).replace('\n', '')
            hsh = gen_key(128, acc)
            akh[acc] = (key, hsh)

        if protocol==3:
            neighbour = dict()
            with open('neighbour.json', 'r') as f:
                neighbour= load(f)
            for elem in neighbour:
                #msg = (akh[elem][0]+akh[elem][1]+proto+user_hash+"%04d"+ua+"%f")%(len(ua), time()-604800)
                #msg = (akh[elem][0]+akh[elem][1]+proto+user_hash+"%04d"+ua+"%f")%(len(ua), accounts['time'])
                for addr in neighbour[elem]['addrs']:
                    try:
                        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                        if sockip!=str():
                            sock.bind((sockip, ri(6000, 10000)))
                        timestamp = "%025f"%(time())
                        proto = '3' if bool(int(read("has_accounts@"+elem))) else '8'
                        neighbour[elem]['type'] = proto
                        ua = bytes(user+'@'+elem, "UTF-8")

                        safe = bytes(timestamp+akh[elem][0]+akh[elem][1]+proto+user_hash, "UTF-8")
                        safe+=bytes("%04d"%(len(ua)), "UTF-8")
                        safe+=ua
                        safe+=bytes("%s"%(str(accounts['time'])), "UTF-8")
         
                        sock.connect((addr, port))
                        sock.send(safe)
                        sock.close()
                    except OSError:
                        pass
            
        if protocol==5:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            if sockip!=str():
                sock.bind((sockip, sockport))
            try:
                timestamp = "%025f"%(time())
                proto = str(protocol)
                ua = bytes(current_user+'@'+acc, "UTF-8")
                safe = bytes(timestamp+akh[acc][0]+akh[acc][1]+proto+user_hash, "UTF-8")
                safe+=bytes("%04d"%(len(ua)), "UTF-8")
                safe+=ua
                sock.connect((ipv6, port))
                sock.send(safe)
                sock.close()
            except OSError:
                pass
        if protocol==6:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            if sockip!=str():
                sock.bind((sockip, sockport))
            if time_of_request!=None:
                neighbour = dict()
                with open('neighbour.json', 'r') as f:
                    neighbour= load(f)
                fname = ('week_data@'+acc) if neighbour[acc][user]['type']=='3' else 'subs@'+acc
                time_of_request = time_of_request if neighbour[acc][user]['type']=='3' else 0
                
                timestamp = "%025f"%(time())
                proto = str(protocol)
                ua = bytes(current_user+'@'+acc, "UTF-8")
                safe = bytes(timestamp+akh[acc][0]+akh[acc][1]+proto+user_hash, "UTF-8")
                safe+=bytes("%04d"%(len(ua)), "UTF-8")
                safe+=ua
                sock.connect((ipv6, port))
                sock.send(safe)

                sizes = list()
                with open(fname+'_size', 'r') as f:
                    sizes = list(map(int, f.read().split()))
                for size in sizes:
                    with open(fname, 'rb') as f:
                        data = f.read(size)
                        T= float(data[0:25].decode())
                        if T>time_of_request:
                            sock.send(data)
            sock.close()
        sleep(0.1)
        sock2 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

        ifi = socket.if_nametoindex(ifn)
        ifis = struct.pack("I", ifi)
        sock2.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, ifis)
        ttl = struct.pack('i', 5)
        sock2.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, ttl)
        if sockip!=str():
            sock2.bind((sockip, sockport))
        for acc in akh:
            if acc!='ip' and acc!='time':
                timestamp = "%025f"%(time())
                sock_addr = socket.getaddrinfo(accounts[acc]['multicast'], port_multi, socket.AF_INET6, socket.SOCK_DGRAM)[0][4]
                ua = current_user+'@'+acc
                sock2.sendto(bytes(timestamp+akh[acc][0]+akh[acc][1]+'2'+"%04d"%(len(ua))+ua+user_hash, 'UTF-8'), sock_addr)
        sock2.close()
    if protocol==4 or protocol==7 or protocol==9:
        key = read(acc).replace('\n','')
        hsh = gen_key(128, acc)
        if current_user == acc:
            user_hash = hsh
        addr=accounts[acc]['multicast']
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

        ifi = socket.if_nametoindex(ifn)
        ifis = struct.pack("I", ifi)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, ifis)
        sock_addr = socket.getaddrinfo(addr, port_multi, socket.AF_INET6, socket.SOCK_DGRAM)[0][4]
        ttl = struct.pack('i', 5)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, ttl)
        if sockip!=str():
            sock.bind((sockip, sockport))
        try:
            ua = bytes(user+'@'+acc, 'UTF-8')
            if protocol==4:
                msg_enc = bytes(msg, "UTF-8")
                safe = bytes(timestamp+key+hsh+str(protocol), 'UTF-8')
                safe += bytes("%04d"%(len(ua)), "UTF-8")+ua
                safe +=bytes("%04d"%(len(msg_enc)), "UTF-8")
                safe +=msg_enc
                with open(msg, 'rb') as f:
                    ss=f.read()
                    safe+=bytes("%012d"%(len(ss)), "UTF-8")
                    safe+=ss
                    safe+=bytes(content, "UTF-8")
                    if user==acc:
                        sock.sendto(safe, sock_addr)
            else:
                msg = bytes(msg, "UTF-8")
                safe = bytes(timestamp+key+hsh+str(protocol), 'UTF-8')
                safe += bytes("%04d"%(len(ua)), "UTF-8")+ua
                safe +=msg
                sock.sendto(safe, sock_addr)
            if user==acc:
                for elem in accounts:
                    if elem!='ip' and elem!='time' and elem!=acc:
                        ua = bytes(current_user+"@"+elem, "UTF-8")
                        key = read(elem).replace('\n','')
                        hsh = gen_key(128, elem)
                        timestamp = "%025f"%(time())
                        safe = bytes(timestamp+key+hsh+'2', "UTF-8")
                        safe+=bytes("%04d"%(len(ua)), "UTF-8")+ua+bytes(user_hash, "UTF-8")
                        addr=accounts[elem]['multicast']
                        sock_addr = socket.getaddrinfo(addr, port_multi, socket.AF_INET6, socket.SOCK_DGRAM)[0][4]
                        sock.sendto(safe, sock_addr)
            sock.close()
        except OSError:
            pass
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

