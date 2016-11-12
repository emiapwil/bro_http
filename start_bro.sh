#!/bin/bash

if [ -z "$1" ]; then
	echo "Usage: $0 INTERFACE"
	exit
fi

DISTO_VERSION="$(cat /proc/version)"

BRO="$(which bro)"

if [ -z "$BRO" ]; then
	if [ ! -z "$(echo $DISTRO_VERSION | grep -i ubuntu)" ]; then
		BRO="/opt/bro/bin/bro"
	elif [ ! -z "$(echo $DISTRO_VERSION | grep -i centos)" ]; then
		BRO="/usr/bin/bro"
	fi
fi

if [ -z "$BRO" ]; then
	echo "Must install bro first!"
	exit
fi

$BRO -C -i $1 conn.bro
