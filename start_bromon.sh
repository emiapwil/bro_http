#!/bin/bash

BRO_DIR=$(dirname $(which $0))

rm -f conn.log http.log

$BRO_DIR/start_bro.sh $1 $2

rm -f _conn.log _http.log
touch _conn.log _http.log

python3 $BRO_DIR/bromon.py $2 _conn.log _http.log &

tail -f conn.log | sed '/^#/d' >> _conn.log &
tail -f http.log | sed '/^#/d' >> _http.log &
