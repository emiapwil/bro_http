#!/bin/bash

INTERFACE=${1:?"Usage: $0 INTERFACE CONTROLLER_IP"}
CONTROLLER_IP=${2:?"Usage: $0 INTERFACE CONTROLLER_IP"}

BRO_DIR=$(dirname $(which $0))

DISTRO_VERSION="$(cat /proc/version)"

BRO="$(which bro)"

if [ -z "$BRO" ]; then
	if [ ! -z "$(echo $DISTRO_VERSION | grep -i ubuntu)" ]; then
		BRO="/opt/bro/bin/bro"
	elif [ ! -z "$(echo $DISTRO_VERSION | grep -i centos)" ]; then
		BRO="/usr/bin/bro"
	fi
fi

BRO=${BRO:?"Must install bro first!"}

pushd $BRO_DIR

cat new_conn.bro | sed "s/\$CONTROLLER_IP/$CONTROLLER_IP/g" > http.bro

$BRO -C -i $INTERFACE http.bro

popd
