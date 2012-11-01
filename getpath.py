#!/usr/bin/env python

import socket
import sys

if len(sys.argv) < 2:
    print "Usage: getpath.py /"
    sys.exit(0)

path = sys.argv[1]

s = socket.socket()
s.connect(('127.0.0.1', 80))
s.sendall("""\
GET %s HTTP/1.0\r
Host: 127.0.0.1\r
\r
""" % path)

data = ''
while True:
    res = s.recv(4096)
    if not res:
        break
    data += res

for L in data.splitlines(1):
    print L.encode('string_escape')
