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
