
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

from flask import Flask, render_template, request, jsonify, make_response, redirect
from json import load, dump
from utils import *
from time import sleep
from os import popen, _exit, path

PWD = popen("pwd").read().replace('\n', '')
app = Flask(__name__, template_folder=PWD)
block_size = 1000
feed= dict()
with open("feed.json") as f:
    feed=load(f)
user = read('current_user').replace('\n', '')
db=[[k, feed[user][k]['title'], feed[user][k]['content'], feed[user][k]['account'], feed[user][k]['link'], feed[user][k]['file'], feed[user][k]['compressed_file']] for k in feed[user]]
posts = len(db)
quantity=20
PORT=5000
@app.route("/")
def index():
    kill = int(read('kill'))
    ex = int(read('exit'))
    if request.method=='GET':
        if kill==1:
            write("kill", '0')
            _exit(0)
        if ex==1:
            _exit(0)
        return render_template("index.html")

@app.route("/exit")
def exitit():
    write('exit', '1')
    return redirect('/')
@app.route('/kill')
def kill():
    write('kill', '1')
    return redirect('/')
@app.route("/load")
def loadit():
    if request.method=='GET':
        counter = int(request.args.get("c"))  # The 'counter' value sent in the QS
        if counter == 0:
            # Slice 0 -> quantity from the db
            res = make_response(jsonify(db[0: min(quantity, posts)]), 200)
        elif counter == posts:
            res = make_response(jsonify({}), 200)
        else:
            #Slice counter -> quantity from the db
            res = make_response(jsonify(db[counter: min(posts, counter+quantity)]), 200)
        return res
@app.route('/get_file')
def get_file():
    key= request.args['key']
    if not bool(int(feed[user][key]['downloaded'])):
        return "<h1>!!!FILE NOT YET DOWNLOADED!!!</h1>"
    if bool(int(feed[user][key]['downloaded'])) and feed[user][key]['file']=='':
        aux = decompress(feed[user][key]['compressed_file'], feed[user][key]['account']+'_folder/')
        feed[user][key]['file']=aux[1]
        feed[user][key]['isFolder']=int(aux[0])#check if isfolder exists for creating file
        with open("feed.json", 'w+') as f:
            dump(feed, f, indent=4)
    if not bool(feed[user][key]['isFolder']):
        fname = feed[user][key]['file']
        ftype = fname.split('.')[-1] if '.' in fname else ""
        if ftype=='txt' or ftype=="":
            popen("""gedit "%s" """%(fname))
        if ftype=='png' or ftype=='jpeg' or ftype=='jpg':
            popen("""shotwell "%s" """%(fname))
        if ftype=='mp4':
            popen("""vlc "%s" """%(fname))
    else:
        popen("""dolphin "%s" """%(fname))
    return redirect("/")

@app.route('/download')
def download():
    key = request.args['key']
    if feed[user].get(key, None)!=None:
        write('kill', '1')
        write('seed_torrent_up', '1')
        torrent_name = magnet_to_torrent(feed[user][key]['link'])
        with open('seeds', 'r') as f:
            seeds = load(f)
        with open('seeds', 'w+') as f:
            seeds[torrent_name] = dict()
            seeds[torrent_name]['key']= key
            seeds[torrent_name]['downloaded']=0
            dump(seeds, f, indent=4)
    return redirect('/')
@app.route('/comment', methods=['POST', 'GET'])
def comment():
    if request.method=='GET':
        acc = request.args['acc']
        k = request.args['key']
        ls = list()
        with open(feed[user][k]['comment'], 'r') as f:
            dfs(ls, load(f))
        ls = [[e[0], e[1], e[2]*5, (e[3][1:len(e[3])] if len(e[3])>0 else e[3])] for e in ls]
        return render_template("comment.html", ls=ls, key=k, acc=acc)
    if request.method=='POST':
        write("kill","1") 
        key, path= request.form['path'].split('@')
        acc = request.form['acc']
        print(user, acc)
        #TODO Organize it here
        msg=(("%04d"+request.form['path']+"%04d"+request.form['new_text'])%(len(request.form['path']), len(request.form['new_text'])))
        send_msg(user=user, acc=acc, proto=7, msg=msg)
        ls = write_msg(request.form["new_text"], feed[user][key]['comment'], path, user)
        ls = [[e[0], e[1], e[2]*5, e[3]] for e in ls]
        return render_template("comment.html", ls=ls, key=key, acc=acc)
@app.route('/submit_post', methods=['POST', 'GET'])
def submit_post():
    if request.method=='GET':
        return render_template("submit_post.html")
    if request.method=='POST':
        write("kill", '1')
        if not request.form.get('link', str()): write('seed_torrent_up', '1')
        title = request.form['title']
        file_path = request.form['file_path']
        content = request.form['content']
        fname = "%s.tar.gz"%(random_str(40)) if not request.form.get('fname', str()) else request.form['fname']
        #fname, link, title, file_path, content
        
        new_hash = sha1(bytes(title+content, 'ascii')).hexdigest()
        with open(user+'_folder/'+new_hash+"@comment", 'w+') as f:
            dump(dict(), f)

        if not request.form.get('link', str()):
            make_tarfile(fname,file_path)
            with open('seeds', 'r') as f:
                seeds = load(f)
            with open('seeds', 'w+') as f:
                seeds[fname+'.torrent']=dict()
                seeds[fname+'.torrent']['key']=new_hash
                seeds[fname+'.torrent']['downloaded']=1
                dump(seeds, f, indent=4)

        link = request.form.get('link', str())
        if not link: link = upload_torrent(fname)

        aux = dict()
        aux[new_hash]=dict()
        aux[new_hash]["title"]=title
        aux[new_hash]["content"]=content
        aux[new_hash]["file"]=file_path
        aux[new_hash]['compressed_file']=fname
        aux[new_hash]["comment"]=user+'_folder/'+new_hash+"@comment"
        aux[new_hash]["account"]=user
        aux[new_hash]['time'] = time()
        aux[new_hash]['downloaded']=1
        aux[new_hash]['isFolder']=int(path.isdir(file_path))
        aux[new_hash]['link'] = link
        aux.update(feed[user])
        feed[user] = aux
        with open('feed.json', 'w+') as f:
            dump(feed, f, indent=4)
        send_msg(user=user, proto=4, acc=user, content=content, title=title, link=link)
        return redirect('/')

@app.route('/login', methods=['POST', 'GET'])
def create_account():
    ifs = interface_names()
    userid = dict()
    with open('userid.json', 'r') as f:
            userid=load(f)
    users = userid.keys()
    if request.method=='GET':
        return render_template('login.html', ifs=list(ifs.keys()), users=users, ifip=interface_ips())
    if request.method=='POST':
        write("kill", '1')
        new_user = request.form["username"]
        if len(new_user)<=15:
            yn = request.form['yn']
            iff = request.form['check']
            write('current_iff_name', iff)
            write('current_dev_name', ifs[iff])
            if userid.get(new_user, None)==None:
                userid[new_user] = random_str(10)
                new_user = new_user+userid[new_user]
                with open('userid.json', 'w+') as f:
                    dump(userid, f, indent=4)
                ipv6 = "None"
                multicast = random_multicast()
                if yn=='y':
                    ipv6=exp_ipv6(request.form["ipv6"])
                tracker_ip = ipv6_rmv_dots(exp_ipv6(request.form["tracker_ipv6"]))
                accounts = dict()
                with open('accounts.json', 'r') as f:
                    accounts = load(f)
                accounts[new_user] = dict()
                accounts[new_user][new_user]= multicast
                accounts[new_user]['time']=time()-604800 #a week
                accounts[new_user]['ip']=ipv6 if ipv6!=str() else 'None'
                accounts[new_user]['tracker_ip'] = tracker_ip
                with open('accounts.json', 'w+') as f:
                    dump(accounts, f, indent=4)
                with open('feed.json', 'r') as f:
                    feed= load(f)
                feed[new_user]=dict()
                with open('feed.json', 'w+') as f:
                    dump(feed, f, indent=4)
                with open('users@'+new_user, 'wb+') as f:
                    f.write(b'0'*block_size)
                with open('users@'+new_user+'_input', 'w+') as f:
                    f.write('0')
                with open('keys@'+new_user, 'wb+') as f:
                    f.write(b'0'*block_size)
                with open('keys@'+new_user+'_input', 'w+') as f:
                    f.write('0')
                with open('ips@'+new_user, 'wb+') as f:
                    f.write(b'0'*block_size)
                with open('ips@'+new_user+'_input', 'w+') as f:
                    f.write('0')
                with open(new_user, 'w+') as f:
                    f.write('')
                with open('subs@'+new_user, 'wb+') as f:
                    f.write(b'')
                with open('subs@'+new_user+'_size', 'w+') as f:
                    f.write('')
                with open('has_accounts@'+new_user, 'w+') as f:
                    f.write('1')
                with open("week_data@"+new_user, 'wb+') as f:
                    f.write(b'')
                with open("week_data@"+new_user+'_size', 'w+') as f:
                    f.write('')
                popen('mkdir %s_folder'%(new_user))
                hsh = gen_key(128, new_user)
                #***
                search(bytes(new_user+'#'*(25-len(new_user))+hsh+ipv6_rmv_dots(multicast)+"0.500000"+hsh+'0'+tracker_ip, 'ascii'), "users@"+new_user, 25,insert=True, update=False)
                write('current_user', new_user)
            else:
                write('current_user', new_user+userid[new_user])
        return redirect('/')
@app.route('/follow')
def follow():
    if request.method=='GET':
        write("kill", '1')
        key= request.args['key']
        acc= request.args['acc']
        res = search(bytes(key+'#'*(user_hash_ip-len(key)), 'ascii'), "users@"+acc, 25, insert=False, update=False)[1]
        multicast = toipv6(res[25+128:25+128+32])
        tracker_ip = res[25+128+32+8+128+1:25+128+32+8+128+1+32]
        accounts = dict()
        with open('accounts.json', 'r') as f:
            accounts = load(f)
        if accounts[user].get(key, None)==None:
            accounts[user][key]=multicast
            popen("mkdir %s_folder"%(key))
            with open('users@'+key, 'wb+') as f:
                f.write(b'0'*block_size)
            with open('users@'+key+'_input', 'w+') as f:
                f.write('0')
            with open('keys@'+key, 'wb+') as f:
                f.write(b'0'*block_size)
            with open('keys@'+key+'_input', 'w+') as f:
                f.write('0')
            with open('ips@'+key, 'wb+') as f:
                f.write(b'0'*block_size)
            with open('ips@'+key+'_input', 'w+') as f:
                f.write('0')
            with open(key, 'w+') as f:
                f.write('')
            with open('subs@'+key, 'wb+') as f:
                f.write(b'')
            with open('subs@'+key+'_size', 'w+') as f:
                f.write('')
            with open('has_accounts@'+key, 'w+') as f:
                f.write('0')
            with open("week_data@"+key, 'wb+') as f:
                f.write(b'')
            with open("week_data@"+key+'_size', 'w+') as f:
                f.write('')
            hsh = res[25+128+32+8:25+128+32+8+128]
            search(bytes(key+'#'*(25-len(key))+hsh+ipv6_rmv_dots(exp_ipv6(multicast))+"0.500000"+hsh+'0'+tracker_ip, 'ascii'), 'users@'+key, 25, insert=True, update=False)
            search(bytes(tracker_ip, 'ascii'), 'ips@'+key, 32, insert=True, update=False)
            with open('accounts.json', 'w+') as f:
                dump(accounts, f, indent=4)
            send_msg(user=user, proto=1, msg=None, acc=key, ipv6=str(), content=str())
        else:
            res = search(bytes(key+'#'*(user_hash_ip-len(key)), 'ascii'), "users@"+acc, 25, insert=False, update=False)[1]
            hsh = res[25+128+32+8:25+128+32+8+128]
            res = search(bytes(key+'#'*(25-len(key))+hsh+ipv6_rmv_dots(exp_ipv6(multicast))+"0.500000"+hsh+'0'+tracker_ip, 'ascii'), 'users@'+key, 25, insert=True, update=False)
        return redirect('/')
@app.route('/info', methods=['GET', 'POST'])
def info():
    kill = int(read('kill'))
    if request.method=='GET':
        if kill==1:
            write("kill", '0')
            _exit(0)
        if user=='None':
            return "<html><h1>You haven't logged in</h1></html>"
        with open('accounts.json', 'r') as f:
            accounts = load(f)[user]
        following = list(accounts.keys())
        following = [k for k in following if k!='time' and k!='ip']
        link = search(bytes(user+'#'*(user_hash_ip-len(user)), 'ascii'), "users@"+user, 25, insert=False, update=False)[1]#**
        return render_template('info.html', link=link, following=following, user=user)
    if request.method=='POST':
        write("kill", '1')
        if request.form.get('block', None)==None:
            delete = request.form['del']
            accounts = dict()
            with open('accounts.json', 'r') as f:
                accounts = load(f)
            if accounts[user].get(delete, None)!=None:
                accounts[user].pop(delete)
            with open('accounts.json', 'w+') as f:
                dump(accounts, f, indent=4)
            feed= dict()
            with open('feed.json', 'r') as f:
                feed= load(f)
            if feed[user].get(delete, None)!=None:
                feed[user].pop(delete)
            with open('feed.json', 'w+') as f:
                dump(feed, f, indent=4)
            popen('rm users@%s'%(delete))
            popen('rm keys@%s'%(delete))
            popen('rm users@%s_input'%(delete))
            popen('rm keys@%s_input'%(delete))
            popen('rm ips@%s'%(delete))
            popen('rm ips@%s_input'%(delete))
            popen('rm week_data@%s'%(delete))
            popen('rm %s'%(delete))
            popen('rm -r -f %s_folder'%(delete))
        else:
            block = request.form['block']
            send_msg(user=user, proto=9, msg=block, acc=user)
            search(bytes(block+'#'*(user_hash_ip-len(block)-1)+'1'+'0'*32, 'ascii'), 'users@'+user, 25, insert=False, update=False)
        return redirect('/info')
@app.route('/add_link', methods=['GET', 'POST'])
def add_link():
    if request.method=='GET':
        return render_template("add_link.html")
    if request.method=='POST':
        write("kill", '1')
        if user=='None':
            return "<html><h1>You haven't logged in</h1></html>"
        link = request.form['link'].replace('http://', '').replace('127.0.0.1:%d/'%(PORT), '').replace('localhost:%d/'%(PORT), '')
        acc = link[0:25].replace('#', '')
#       user_hash_ip = 25+128+32+8+128+1+32 
        multicast = toipv6(link[25+128:25+128+32])
        tracker_ip = link[25+128+32+8+128+1:]
        accounts = dict()
        with open('accounts.json', 'r') as f:
            accounts = load(f)
        if accounts[user].get(acc, None)==None:
            write('kill', '1')
            accounts[user][acc]=multicast
            popen("mkdir %s_folder"%(acc))
            with open('users@'+acc, 'wb+') as f:
                f.write(b'0'*block_size)
            with open('users@'+acc+'_input', 'w+') as f:
                f.write('0')
            with open('keys@'+acc, 'wb+') as f:
                f.write(b'0'*block_size)
            with open('keys@'+acc+'_input', 'w+') as f:
                f.write('0')
            with open('ips@'+acc, 'wb+') as f:
                f.write(b'0'*block_size)
            with open('ips@'+acc+'_input', 'w+') as f:
                f.write('0')
            with open(acc, 'w+') as f:
                f.write('')
            with open('subs@'+acc, 'wb+') as f:
                f.write(b'')
            with open('subs@'+acc+'_size', 'w+') as f:
                f.write('')
            with open('has_accounts@'+acc, 'w+') as f:
                f.write('0')
            with open("week_data@"+acc, 'wb+') as f:
                f.write(b'')
            with open("week_data@"+acc+'_size', 'w+') as f:
                f.write('')
            search(bytes(link, 'ascii'), "users@"+acc, 25, insert=True, update=False)
            search(bytes(tracker_ip, 'ascii'), 'ips@'+acc, 32, insert=True, update=False)
            with open('accounts.json', 'w+') as f:
                dump(accounts, f, indent=4)
            send_msg(user=user, proto=1, msg=None, acc=acc, ipv6=str(), content=str())
        else:
            search(bytes(link, 'ascii'), "users@"+acc, 25, insert=False, update=True)
        return redirect('/')
try:
    app.run(port=PORT)
except OSError:
    _exit(0)
