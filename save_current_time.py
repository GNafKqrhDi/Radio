from json import load, dump
from time import time
current_user = str()
with open("current_user", 'r') as f:
    current_user = f.read()
accounts = dict()
with open("accounts.json", 'r') as f:
    accounts=load(f)
if accounts.get(current_user, None)==None:
    exit()
accounts[current_user]['time'] = time()
with open("accounts.json", 'w+') as f:
    dump(accounts, f, indent=4)
with open("neighbour.json", "w+") as f:
    dump(dict(), f, indent=4)
