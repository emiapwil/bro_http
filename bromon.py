#!/usr/bin/env python3

from multiprocessing import Process, Lock, Manager
import sys
import urllib.parse, requests
import json

URL="http://{}:8181/restconf/config/fast-caltechdemo-flowmetadata:crosslayer-flow-metadata/flow-metadata/{}"
HEADER={"content-type": "application/json"}

def flow_hash(conn):
    src_ip = conn['src-ip']
    dst_ip = conn['dst-ip']
    src_port = str(conn['src-port'])
    dst_port = str(conn['dst-port'])
    proto = 'tcp' if conn['ip-proto']  == 6 else 'udp'
    return '<' + ','.join([proto, src_ip, src_port, dst_ip, dst_port]) + ">"

def make_request(controller_ip, conn, http):
    flow_id = flow_hash(conn)

    conn['flow-id'] = flow_id
    conn['http-metadata'] = http
    flow_meta = { 'flow-metadata': conn }

    data = json.dumps(flow_meta)
    print(data)

    url = URL.format(controller_ip.value, urllib.parse.quote_plus(flow_id))
    print(url)

    r = requests.put(url, data=data, headers=HEADER, auth=("admin", "admin"))
    print(r.text)

def ensure_info(info, key):
    if key in info:
        return info[key]
    else:
        info[key] = {'conn': []}
        return info[key]

def update_conn(info, lock, controller_ip, key, cinfo):
    lock.acquire()

    data = ensure_info(info, key)

    data['conn'] += [cinfo]

    if 'http' in data:
        for conn in data['conn']:
            make_request(controller_ip, conn, data['http'])
        data['conn'] = []

    info[key] = data

    lock.release()

def update_http(info, lock, controller_ip, key, hinfo):
    lock.acquire()

    data = ensure_info(info, key)
    data['http'] = hinfo

    for conn in data['conn']:
        make_request(controller_ip, conn, data['http'])
    data['conn'] = []

    info[key] = data

    lock.release()

def monitor_http(info, lock, controller_ip, line):
    hinfo = line.split('\t')
    key = hinfo[1]
    http = {
            "uri": hinfo[9],
            "user-agent": hinfo[11],
            "content-length": int(hinfo[13]),
            "filename": "" if hinfo[19] == '(empty)' else hinfo[19],
            "mime-type": [ hinfo[26] ]
            }
    update_http(info, lock, controller_ip, key, http)

def monitor_conn(info, lock, controller_ip, line):
    cinfo = line.split('\t')
    key = cinfo[1]
    conn = {
            "src-ip": cinfo[2],
            "src-port": int(cinfo[3]),
            "dst-ip": cinfo[4],
            "dst-port": int(cinfo[5]),
            "ip-proto": 6 if cinfo[6].lower() == 'tcp' else 17
            }
    update_conn(info, lock, controller_ip, key, conn)

def monitor_file(filename, consumer):
    f = open(filename, "r")

    while True:
        line = f.readline().rstrip('\r\n')
        if len(line) > 0:
            consumer(line)

if __name__ == '__main__':
    global info, lock

    manager = Manager()

    info = manager.dict()
    lock = manager.Lock()
    controller_ip = manager.Value('s', sys.argv[1])

    consume_conn = lambda line: monitor_conn(info, lock, controller_ip, line)
    consume_http = lambda line: monitor_http(info, lock, controller_ip, line)

    p1 = Process(target=monitor_file, args=(sys.argv[2], consume_conn))
    p2 = Process(target=monitor_file, args=(sys.argv[3], consume_http))

    p1.start()
    p2.start()

    p1.join()
    p2.join()
