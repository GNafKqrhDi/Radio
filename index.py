from flask import Flask, render_template, request, jsonify, make_response, redirect
from json import load, dump
from utils import *
from time import sleep
from os import popen, _exit

app = Flask(__name__, template_folder="./")
BLOCK_SIZE = 1000

feed = dict()
with open("feed.json") as f:
    feed=load(f)
user_hash_ip = 25+128+32+8+128+1
user = read('current_user').replace('\n', '')
feed = feed[user]
db=[['➢'.join(feed[k]['title'].split('_folder/')), feed[k]['content'], feed[k]['file'], k, feed[k]['account']] for k in feed]
posts = len(db)
quantity=20
PORT=5000
@app.route("/")
def index():
    kill = int(read('kill'))
    if request.method=='GET':
        if kill==1:
            write("kill", '0')
            _exit(0)
        return render_template("index.html")

@app.route("/exit")
def exit():
    write('exit', '1')
    _exit(0)
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
            # Slice counter -> quantity from the db
            res = make_response(jsonify(db[counter: min(posts, counter+quantity)]), 200)
        return res
@app.route('/get_file')
def get_file():
    if request.method=='GET':
        fname = request.args['fname']
        ftype = fname.split('.')[-1] if '.' in fname else ""
        if ftype=='txt' or ftype=="":
            popen("""gedit "%s" """%(fname))
        if ftype=='png' or ftype=='jpeg' or ftype=='jpg':
            popen("""shotwell "%s" """%(fname))
        if ftype=='mp4':
            popen("""vlc "%s" """%(fname))
        return redirect("/")

@app.route('/comment', methods=['POST', 'GET'])
def comment():
    if request.method=='GET':
        acc = request.args['acc']
        k = request.args['key']
        ls = list()
        with open(feed[k]['comment'], 'r') as f:
            dfs(ls, load(f))
        ls = [[e[0], e[1], e[2]*5, (e[3][1:len(e[3])] if len(e[3])>0 else e[3])] for e in ls]
        return render_template("comment.html", ls=ls, key=k, acc=acc)
    if request.method=='POST':
        write("kill","1") 
        key, path= request.form['path'].split('@')
        acc = request.form['acc']
        flag=True
        if flag:
            print(user, acc)
            msg=(("%04d"+request.form['path']+"%04d"+request.form['new_text'])%(len(request.form['path']), len(request.form['new_text'])))
            send_msg(user=user, acc=acc, protocol=7, msg=msg)
            ls = write_msg(request.form["new_text"], feed[key]['comment'], path, user)
            ls = [[e[0], e[1], e[2]*5, e[3]] for e in ls]
            return render_template("comment.html", ls=ls, key=key, acc=acc)
    return redirect("/", key=key, acc=acc)
@app.route('/submit_post', methods=['POST', 'GET'])
def submit_post():
    if request.method=='GET':
        return render_template("submit_post.html")
    if request.method=='POST':
        write("kill", '1')
        ff = request.files['file']
        fname = request.form['title']
        ftype = ff.filename.split('.')[-1] if '.' in ff.filename else ""
        ff.save(user+'_folder/'+fname+'.'+ftype)
        del ff
        ff = b''
        with open(user+'_folder/'+fname+'.'+ftype, 'rb') as f:
            ff= f.read()
        content = request.form['content']
        new_hash = sha512(ff+bytes(content, 'UTF-8')).hexdigest()
        with open(user+'_folder/'+new_hash+"@comment", 'w+') as f:
            dump(dict(), f)
        with open('feed.json', 'r') as f:
            feed = load(f)
        if feed.get(user, None)==None:
            feed[user]=dict()
        aux = dict()
        aux[new_hash]=dict()
        aux[new_hash]["title"]=user+"_folder/"+fname
        aux[new_hash]["content"]=content
        aux[new_hash]["file"]=user+'_folder/'+fname+'.'+ftype
        aux[new_hash]["comment"]=user+'_folder/'+new_hash+"@comment"
        aux[new_hash]["account"]=user
        aux[new_hash]['time'] = time()
        aux.update(feed[user])
        feed[user] = aux
        with open('feed.json', 'w+') as f:
            dump(feed, f, indent=4)
        send_msg(user=user, protocol=4, msg=user+'_folder/'+fname+'.'+ftype, acc=user, content=content)
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
                accounts = dict()
                with open('accounts.json', 'r') as f:
                    accounts = load(f)
                accounts[new_user] = dict()
                accounts[new_user][new_user]=dict()
                accounts[new_user][new_user]['multicast']= multicast
                accounts[new_user]['time']=time()-604800 #a week
                accounts[new_user]['ip']=ipv6
                with open('accounts.json', 'w+') as f:
                    dump(accounts, f, indent=4)
                with open('feed.json', 'r') as f:
                    feed = load(f)
                feed[new_user]=dict()
                with open('feed.json', 'w+') as f:
                    dump(feed, f, indent=4)
                with open('users@'+new_user, 'wb+') as f:
                    f.write(b'0'*BLOCK_SIZE)
                with open('users@'+new_user+'_input', 'w+') as f:
                    f.write('0')
                with open('keys@'+new_user, 'wb+') as f:
                    f.write(b'0'*BLOCK_SIZE)
                with open('keys@'+new_user+'_input', 'w+') as f:
                    f.write('0')
                with open('ips@'+new_user, 'wb+') as f:
                    f.write(b'0'*BLOCK_SIZE)
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
                with open("week_data"+new_user, 'wb+') as f:
                    f.write(b'')
                with open("week_data"+new_user+'_size', 'w+') as f:
                    f.write('')
                popen('mkdir %s_folder'%(new_user))
                hsh = gen_key(128, new_user)
                search(bytes(new_user+'#'*(25-len(new_user))+hsh+ipv6_rmv_dots(multicast)+"0.500000"+hsh+'0', 'ascii'), "users@"+new_user, 25,insert=True, update=False)
                write('current_user', new_user)
            else:
                write('current_user', new_user+userid[new_user])
        return redirect('/')
@app.route('/follow')#window.location.href='/follow?key=atilaBuJUx3znqn&acc=atilaueryBmIVwG';
def follow():#TODO make it dynamically allocate memory when searching
    if request.method=='GET':
        write("kill", '1')
        key= request.args['key']
        acc= request.args['acc']
        res = search(bytes(key+'#'*(user_hash_ip-len(key)), 'ascii'), "users@"+acc, 25, insert=False, update=False)[1]
        multicast = toipv6(res[25+128:25+128+32])
        accounts = dict()
        with open('accounts.json', 'r') as f:
            accounts = load(f)
        if accounts[user].get(key, None)==None:
            accounts[user][key]=dict()
            accounts[user][key]['multicast']=multicast
            popen("mkdir %s_folder"%(key))
            with open('users@'+key, 'wb+') as f:
                f.write(b'0'*BLOCK_SIZE)
            with open('users@'+key+'_input', 'w+') as f:
                f.write('0')
            with open('keys@'+key, 'wb+') as f:
                f.write(b'0'*BLOCK_SIZE)
            with open('keys@'+key+'_input', 'w+') as f:
                f.write('0')
            with open('ips@'+key, 'wb+') as f:
                f.write(b'0'*BLOCK_SIZE)
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
            with open("week_data"+key, 'wb+') as f:
                f.write(b'')
            with open("week_data"+key+'_size', 'w+') as f:
                f.write('')
            hsh = res[25+128+32+8:25+128+32+8+128]
            search(bytes(key+'#'*(25-len(key))+hsh+ipv6_rmv_dots(exp_ipv6(multicast))+"0.500000"+hsh+'0', 'ascii'), 'users@'+key, 25, insert=True, update=False)
            with open('accounts.json', 'w+') as f:
                dump(accounts, f, indent=4)
            send_msg(user=user, protocol=1, msg=None, acc=key, ipv6=str(), content=str())
        else:
            res = search(bytes(key+'#'*(user_hash_ip-len(key)), 'ascii'), "users@"+acc, 25, insert=False, update=False)[1]
            hsh = res[25+128+32+8:25+128+32+8+128]
            res = search(bytes(key+'#'*(25-len(key))+hsh+ipv6_rmv_dots(exp_ipv6(multicast))+"0.500000"+hsh+'0', 'ascii'), 'users@'+key, 25, insert=True, update=False)
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
                feed = load(f)
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
            send_msg(user=user, protocol=9, msg=block, acc=user)
            search(bytes(block+'#'*(user_hash_ip-len(block)-1)+'1', 'ascii'), 'users@'+user, 25, insert=False, update=False)
        return redirect('/info')
@app.route('/add_link', methods=['GET', 'POST'])
def add_link():#TODO check if link is valid
    if request.method=='GET':
        return render_template("add_link.html")
    if request.method=='POST':
        write("kill", '1')
        if user=='None':
            return "<html><h1>You haven't logged in</h1></html>"
        link = request.form['link'].replace('http://', '').replace('127.0.0.1:%d/'%(PORT), '').replace('localhost:%d/'%(PORT), '')
        acc = link[0:25].replace('#', '')
        multicast = toipv6(link[25+128:25+128+32])
        accounts = dict()
        with open('accounts.json', 'r') as f:
            accounts = load(f)
        if accounts.get(acc, None)==None:
            accounts[user][acc]=dict()
            accounts[user][acc]['multicast']=multicast
            popen("mkdir %s_folder"%(acc))
            with open('users@'+acc, 'wb+') as f:
                f.write(b'0'*BLOCK_SIZE)
            with open('users@'+acc+'_input', 'w+') as f:
                f.write('0')
            with open('keys@'+acc, 'wb+') as f:
                f.write(b'0'*BLOCK_SIZE)
            with open('keys@'+acc+'_input', 'w+') as f:
                f.write('0')
            with open('ips@'+acc, 'wb+') as f:
                f.write(b'0'*BLOCK_SIZE)
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
            with open("week_data"+acc, 'wb+') as f:
                f.write(b'')
            with open("week_data"+acc+'_size', 'w+') as f:
                f.write('')
            search(bytes(link, 'ascii'), "users@"+acc, 25, insert=True, update=False)
            with open('accounts.json', 'w+') as f:
                dump(accounts, f, indent=4)
            send_msg(user=user, protocol=1, msg=None, acc=acc, ipv6=str(), content=str())
        else:
            search(bytes(link, 'ascii'), "users@"+acc, 25, insert=False, update=True)
        return redirect('/')
try:
    app.run(port=PORT)
except OSError:
    exit()

