from utils import *
from json import dump, load
from hashlib import sha512
from time import time, sleep
sleep(20)
if not bool(int(read("login"))):
    exit(0)
current_user = read("current_user").replace('\n', '')
if current_user=='None':
    exit(0)
write("login", '1')
accounts = dict()
with open("accounts.json") as f:
    accounts=load(f)
accounts = accounts[current_user]
neighbour = dict()
with open('neighbour.json', 'r') as f:
    neighbour = load(f)

user_hash_ip = 25+128+32+8+128+1
for acc in neighbour:
    files = dict()
    good_hashes = list()
    if len(neighbour[acc])>3:
        write('has_accounts@'+acc, '1')
    T = float(accounts['time']) if neighbour[acc].get('type', None)==3 else 0
    for n in neighbour[acc]:
        if n!='addrs' and n!='count' and n!='type':
            P = float(neighbour[acc][n]['prob'])
            sizes = list()
            try:
                with open('%s@%s_size'%(neighbour[acc][n]['num'], acc), 'r') as f:
                    sizes = list(map(int, f.read().split()))
            except FileNotFoundError:
                exit()
            with open('%s@%s'%(neighbour[acc][n]['num'], acc), 'rb') as f:
                for size in sizes:
                    data=f.read(size)
                    timestamp = data[0:25].decode()
                    if timestamp:
                        timestamp = float(timestamp)
                        new_hash=sha512(data).hexdigest()
                        if files.get(timestamp, None)==None:
                            files[timestamp] = dict()
                            files[timestamp]['prob'] = dict()
                            files[timestamp]['prob'][new_hash]=[P]
                        else:
                            files[timestamp]['prob'][new_hash].append(P)
                        files[timestamp][n]=new_hash
    for k in files:
        for n in neighbour[acc]:
            if n!='addrs' and n!='count' and n!='type':
                P = float(neighbour[acc][n]['prob'])
                if files[k].get(n, None)==None:
                    files[k][n]='*'
                    if files[k]['prob'].get('*', None)==None:
                        files[k]['prob']['*']=[P]
                    else:
                        files[k]['prob']['*'].append(P)
        probs = estimate_probability(files[k]['prob'])
        probs = {h:((round(probs[h], 6)), len(files[k]['prob'][h])) for h in probs}
        max_hash = max(probs, key=lambda x:probs[x])
        good_hashes.append(max_hash)
        for n in neighbour[acc]:
            if n!='addrs' and n!='count' and n!='type':
                res = search(bytes(n+'#'*(user_hash_ip-len(n)), 'ascii'), 'users@'+acc, 25, insert=False, update=False)
                P = float(neighbour[acc][n]['prob'])
                P = ((1+19*P)/20 if files[k][n]==max_hash else (1+18*P)/20)
                res = res[1][:25+128+32]+"%.6f"%(P)+res[1][25+128+32+8:]
                search(bytes(res,'ascii'), 'users@'+acc, 25, insert=False, update=True)
    vis = {h:False for h in good_hashes}
    for n in neighbour[acc]:
        if n!='addrs' and n!='count' and n!='type':
            size_aux, size_week = list(), list()
            with open('%s@%s_size'%(neighbour[acc][n]['num'], acc), 'rb') as f:
                size_aux = list(map(int, f.read().split()))
            with open('week_data@'+acc+'_size', 'rb') as f:
                size_week = list(map(int, f.read().split()))
            with open('%s@%s'%(neighbour[acc][n]['num'], acc), 'rb') as f:
                with open('week_data@'+acc, 'rb') as week:
                    with open('week_data@'+acc+'_tmp', 'wb+') as tmp:
                        with open('week_data@'+acc+"_size", "w+") as new_size:
                            data, data2 = f.read(size_aux[0]) if size_aux else str(), week.read(size_week[0]) if size_week else str()
                            t1, t2 = data[0:25].decode(), data2[0:25].decode()
                            t1, t2 = float(t1) if t1 else 0, float(t2) if t2 else 0
                            while (data and data2):
                                if (t1<t2):
                                    check = sha512(data).hexdigest()
                                    if vis.get(check, None)!=None and not vis[check]:
                                        if t1>T:
                                            tmp.write(data)
                                            new_size.write("%d "%(size_aux[0]))
                                        vis[check]=True
                                        #process_multicast(data, current_user, accounts)
                                    size_aux.pop(0)
                                    if size_aux:
                                        data = f.read(size_aux[0]) 
                                        t1 = float(data[0:25]) if size_aux else 0
                                    else:
                                        data=str()
                                else:
                                    check = sha512(data2).hexdigest()
                                    if vis.get(check, None)!=None and not vis[check]:
                                        if t1>T:
                                            tmp.write(data2)
                                            new_size.write("%d "%(size_week[0]))
                                        vis[check]=True
                                    size_week.pop(0)
                                    if size_week:
                                        data2 = week.read(size_week[0])
                                        t2 = float(data2[0:25].decode()) if size_week else 0
                                    else:
                                        data2=str()

                            while data:
                                check = sha512(data).hexdigest()
                                if vis.get(check, None)!=None and not vis[check]:
                                    if t1>T:
                                        tmp.write(data)
                                        new_size.write("%d "%(size_aux[0]))
                                    vis[check]=True
                                size_aux.pop(0)
                                if size_aux:
                                    data = f.read(size_aux[0])
                                    t1 = float(data[0:25].decode())
                                else:
                                    data=str()
                            while data2:
                                check = sha512(data2).hexdigest()
                                if vis.get(check, None)!=None and not vis[check]:
                                    if t2>T:
                                        tmp.write(data2)
                                        new_size.write("%d "%(size_week[0]))
                                    vis[check]=True
                                size_week.pop(0)
                                if size_week:
                                    data2 = week.read(size_week[0])
                                    t2 = float(data2[0:25].decode())
                                else:
                                    data2=str()
            with open('week_data@'+acc+'_tmp', 'rb') as tmp:
                with open('week_data@'+acc, 'wb+') as week:
                    c=tmp.read(1)
                    while c:
                        week.write(c)
                        c=tmp.read(1)
            with open('%s@%s'%(neighbour[acc][n]['num'], acc), 'wb+') as f:
                f.write(b"")
            with open('week_data@'+acc+'_tmp', 'wb+') as tmp:
                tmp.write(b"")
    if len(neighbour[acc]['addrs'])>0:
        sizes = list()
        with open("week_data@"+acc+'_size', 'r') as f:
            sizes = list(map(int, f.read().split()))
        with open("week_data@"+acc, 'rb') as f:
            for size in sizes:
                data = f.read(size)
                process_multicast(data, current_user, accounts)
