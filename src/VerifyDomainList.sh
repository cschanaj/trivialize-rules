#!/bin/bash

while read host; 
do
	curl -s -I --max-time 20 "https://$host" -o /dev/null
	if [ $? -ne 0 ]; then
		echo "Error: 'curl' failed for host $host"
		echo "Exited with error code 1"
		exit 1
	else 
		echo "Info : 'curl' host $host done successfully"
	fi
done < $1

echo "Exited without any error"
