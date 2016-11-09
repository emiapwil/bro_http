#!/bin/bash

if [ -z "$1" ]; then
	echo "Usage: $0 INTERFACE"
	exit
fi

/opt/bro/bin/bro -C -i $1 conn.bro
