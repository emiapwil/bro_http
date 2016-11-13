#!/bin/bash

BRO_DIR=$(dirname $(which $0))

rm -f conn.log http.log
touch conn.log http.log

$BRO_DIR/start_bro.sh $1 $2

python3 $BRO_DIR/bromon.py $2 conn.log http.log

