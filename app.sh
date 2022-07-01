#!/bin/bash
seed_pid=""
while true
do
	pids=()
	if [ "$(cat "exit")" = "1" ];then
		echo "0" > "exit"
		echo "0" > "login"
        echo "0" > "seed_torrent_up"
		kill "$seed_pid"
        python3 save_current_time.py
		exit
	else
        if [ "$(cat "seed_torrent_up")" = "1" ];then
            kill "$seed_pid"
            echo "0" > "seed_torrent_up"
            python3 seed_torrent.py &
            seed_pid=($!)
            python3 listen_to_multicast.py &
            pids+=($!)
            python3 process_network.py &
            pids+=($!)
            python3 server.py &
            pids+=($!) 
            python3 check_files.py &
            pids+=($!)
            python3 index.py
        else
            python3 listen_to_multicast.py &
            pids+=($!)
            python3 process_network.py &
            pids+=($!)
            python3 server.py &
            pids+=($!)
            python3 check_files.py &
            pids+=($!)
            python3 index.py
		fi
        for p in "${pids[@]}" ; do kill "$p"; done
	fi
done
