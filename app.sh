#!/bin/bash
while true
do
	pids=()
	if [ "$(cat "exit")" = "1" ];then
		echo "0" > "exit"
		echo "0" > "login"
		python3 save_current_time.py
		exit
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
		for p in "${pids[@]}" ; do kill "$p"; done
		echo "1" > "login"
	fi
done
