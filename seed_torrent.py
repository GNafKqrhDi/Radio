
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
import libtorrent as lt
from json import load, dump
from os import popen
from time import sleep
import sys
with open('current_user', 'r') as f:
    user = f.read().replace('\n', '')
with open("seeds", 'r') as f:
    seeds = load(f)
ses = lt.session()
ses.listen_on(6881, 6891)
handles=dict()
for torrent in seeds:
    handles[torrent] = ses.add_torrent({'ti':lt.torrent_info(torrent), 'save_path':'./'})
ses.start_dht()
while True:
    sleep(5)
    for torrent in handles:
        s = handles[torrent].status()
        state_str = ['queued', 'checking', 'downloading metadata', \
          'downloading', 'finished', 'seeding', 'allocating', 'checking fastresume']

        print('\r%.2f%% complete (down: %.1f kb/s up: %.1f kB/s peers: %d) %s' % \
          (s.progress * 100, s.download_rate / 1000, s.upload_rate / 1000, s.num_peers, state_str[s.state]))
        sys.stdout.flush()
        sleep(1)
        if s.progress==1.0 and not bool(int(seeds[torrent]['downloaded'])):
            seeds[torrent]['downloaded']=1
            with open('seeds', 'w+') as f:
                dump(seeds, f, indent=4)
            with open('feed.json', 'r') as f:
                feed = load(f)
            with open('feed.json', 'w+') as f:
                feed[user][seeds[torrent]['key']]['downloaded']=1
                feed[user][seeds[torrent]['key']]['compressed_file']=torrent.replace('.torrent', '')
                dump(feed, f, indent=4)
            kill_server()
