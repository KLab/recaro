import socket

s = socket.socket()
s.connect(('127.0.0.1', 11211))

def mcset(key, val):
    s.sendall("set %s 0 0 %d\r\n%s\r\n" % (key, len(val), val))

mcset('/foo', """\
text/plain\r
fizzbuzz
""")

mcset('/bar', """\
text/html\r
1
2
<!--# include fizz -->
4
<!--# include buzz -->
<!--# include fizz -->
7
8
<!--# include fizz -->
<!--# include buzz -->
11
""")

mcset('fizz', 'FIZZ')
mcset('buzz', 'BUZZ')
