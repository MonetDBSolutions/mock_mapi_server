# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright MonetDB Solutions B.V. 2019

import logging
import socket
from threading import Thread

LOGGER = logging.getLogger(__name__)
MLEN = 512
# The first two bytes of each message are the length of the message. The max
# number of bytes we can send in an 8k block is 8190 (8K - 2 bytes.)
MAX_BLOCK_LEN = 8190

# listen for connections
# for each incoming connection, spawn a thread to serve


def send_message(connection, msg):
    if msg == "":
        connection.send(b'\x01\00')
        return

    msg_bytes = msg.encode('utf-8')
    while len(msg_bytes) > 0:
        snd_bytes = msg_bytes[:MAX_BLOCK_LEN]
        ln = ((len(snd_bytes) << 1) + 1).to_bytes(2, 'little')
        connection.send(ln + snd_bytes)

        msg_bytes = msg_bytes[MAX_BLOCK_LEN + 1:]


def receive_message(connection):
    buf = connection.recv(2)
    ln = (int.from_bytes(buf, 'little') - 1) >> 1
    # eof from client
    if ln < 0:
        return b""
    buf = connection.recv(ln)
    return buf


def handler(connection):
    # Send the challenge
    challenge = 'udkTtkbSrcl:mserver:9:PROT10,RIPEMD160,SHA256,SHA1,MD5,COMPRESSION_SNAPPY,COMPRESSION_LZ4:LIT:SHA512:'
    send_message(connection, challenge)
    buf = receive_message(connection)  # Login challenge response
    print("Received 1 %s" % buf)

    send_message(connection, "")
    buf = receive_message(connection)  # profiler.setheartbeat()
    print("Received 2 %s" % buf)

    send_message(connection, "")
    buf = receive_message(connection)  # profiler.openstream()
    print("Received 3 %s" % buf)

    with open('/home/kutsurak/work/monet/sources/mdb-lite/mal_analytics/tests/data/traces/jan2019_sf10_10threads/Q01_variation001.json') as fl:
        lines = fl.readlines()
        for i in range(5):
            for l in lines:
                send_message(connection, l)

    buf = receive_message(connection)
    print("Received 4 %s" % buf)


def start_server(server_address=('localhost', 50000)):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Starting mock server on %s:%d" % (server_address[0], server_address[1]))
    sock.bind(server_address)
    sock.listen(2)

    # while(True):
    connection, address = sock.accept()
    print("Accepted connection from {}".format(address))
    thread = Thread(target = handler, args=(connection,))
    thread.start()
    thread.join()


def main():
    LOGGER.setLevel(logging.DEBUG)
    start_server()


if __name__ == '__main__':
    main()

# server: 2019/07/02 15:54:42.284632  length=103 from=0 to=102
#  cb 00 75 64 6b 54 74 6b 62 53 72 63 6c 3a 6d 73  ..udkTtkbSrcl:ms
#  65 72 76 65 72 3a 39 3a 50 52 4f 54 31 30 2c 52  erver:9:PROT10,R
#  49 50 45 4d 44 31 36 30 2c 53 48 41 32 35 36 2c  IPEMD160,SHA256,
#  53 48 41 31 2c 4d 44 35 2c 43 4f 4d 50 52 45 53  SHA1,MD5,COMPRES
#  53 49 4f 4e 5f 53 4e 41 50 50 59 2c 43 4f 4d 50  SION_SNAPPY,COMP
#  52 45 53 53 49 4f 4e 5f 4c 5a 34 3a 4c 49 54 3a  RESSION_LZ4:LIT:
#  53 48 41 35 31 32 3a                             SHA512:
# --
# client: 2019/07/02 15:54:42.285160  length=2 from=0 to=1
#  a9 00                                            ..
# --
# client: 2019/07/02 15:54:42.285303  length=84 from=2 to=85
#  4c 49 54 3a 6d 6f 6e 65 74 64 62 3a 7b 52 49 50  LIT:monetdb:{RIP
#  45 4d 44 31 36 30 7d 32 36 38 61 62 36 39 31 62  EMD160}268ab691b
#  37 38 66 38 61 39 39 36 33 39 65 30 32 66 64 35  78f8a99639e02fd5
#  63 61 66 30 33 37 30 36 39 61 61 34 63 35 34 3a  caf037069aa4c54:
#  6d 61 6c 3a 64 65 6d 6f 3a 46 49 4c 45 54 52 41  mal:demo:FILETRA
#  4e 53 3a 0a                                      NS:.
# --
# server: 2019/07/02 15:54:42.285763  length=2 from=103 to=104
#  01 00                                            ..
# --
# client: 2019/07/02 15:54:42.285890  length=2 from=86 to=87
#  35 00                                            5.
# --
# client: 2019/07/02 15:54:42.286006  length=26 from=88 to=113
#  70 72 6f 66 69 6c 65 72 2e 73 65 74 68 65 61 72  profiler.sethear
#  74 62 65 61 74 28 30 29 3b 0a                    tbeat(0);.
# --
# server: 2019/07/02 15:54:42.286211  length=2 from=105 to=106
#  01 00                                            ..
# --
# client: 2019/07/02 15:54:42.286354  length=2 from=114 to=115
#  33 00                                            3.
# --
# client: 2019/07/02 15:54:42.286455  length=25 from=116 to=140
#  20 70 72 6f 66 69 6c 65 72 2e 6f 70 65 6e 73 74   profiler.openst
#  72 65 61 6d 28 33 29 3b 0a                       ream(3);.
# --
# server: 2019/07/02 15:54:42.286626  length=2 from=107 to=108
#  01 00                                            ..
# --
# client: 2019/07/02 15:54:44.082120  length=19 from=141 to=159
#  23 00 70 72 6f 66 69 6c 65 72 2e 73 74 6f 70 28  #.profiler.stop(
#  29 3b 0a                                         );.
# --
# server: 2019/07/02 15:54:44.083061  length=2 from=109 to=110
#  7d 03                                            }.
# --
# server: 2019/07/02 15:54:44.083366  length=448 from=111 to=558
#  7b 22 76 65 72 73 69 6f 6e 22 3a 22 31 31 2e 33  {"version":"11.3
#  33 2e 34 20 28 68 67 20 69 64 3a 20 39 32 35 38  3.4 (hg id: 9258
#  63 66 63 65 37 65 63 30 2b 29 22 2c 22 73 6f 75  cfce7ec0+)","sou
#  72 63 65 22 3a 22 74 72 61 63 65 22 2c 22 63 6c  rce":"trace","cl
#  6b 22 3a 39 36 37 32 38 37 39 34 30 2c 22 63 74  k":967287940,"ct
#  69 6d 65 22 3a 31 35 36 32 30 37 35 36 38 35 39  ime":15620756859
#  35 39 30 35 30 2c 22 74 68 72 65 61 64 22 3a 37  59050,"thread":7
#  2c 22 66 75 6e 63 74 69 6f 6e 22 3a 22 75 73 65  ,"function":"use
#  72 2e 6d 61 69 6e 22 2c 22 70 63 22 3a 30 2c 22  r.main","pc":0,"
#  74 61 67 22 3a 38 33 36 2c 22 6d 6f 64 75 6c 65  tag":836,"module
#  22 3a 22 75 73 65 72 22 2c 22 69 6e 73 74 72 75  ":"user","instru
#  63 74 69 6f 6e 22 3a 22 6d 61 69 6e 22 2c 22 73  ction":"main","s
#  65 73 73 69 6f 6e 22 3a 22 30 30 64 34 38 33 34  ession":"00d4834
#  61 2d 33 37 66 65 2d 34 34 36 62 2d 39 38 61 64  a-37fe-446b-98ad
#  2d 39 33 37 37 65 34 64 32 63 64 39 64 22 2c 22  -9377e4d2cd9d","
#  73 74 61 74 65 22 3a 22 73 74 61 72 74 22 2c 22  state":"start","
#  75 73 65 63 22 3a 31 30 2c 22 72 73 73 22 3a 38  usec":10,"rss":8
#  39 2c 22 73 69 7a 65 22 3a 30 2c 22 6e 76 63 73  9,"size":0,"nvcs
#  77 22 3a 32 35 31 2c 22 73 74 6d 74 22 3a 22 66  w":251,"stmt":"f
#  75 6e 63 74 69 6f 6e 20 75 73 65 72 2e 6d 61 69  unction user.mai
#  6e 28 29 3a 76 6f 69 64 3b 22 2c 22 73 68 6f 72  n():void;","shor
#  74 22 3a 22 66 75 6e 63 74 69 6f 6e 20 75 73 65  t":"function use
#  72 2e 6d 61 69 6e 28 20 29 22 2c 22 70 72 65 72  r.main( )","prer
#  65 71 22 3a 5b 5d 2c 22 72 65 74 22 3a 5b 7b 22  eq":[],"ret":[{"
#  69 6e 64 65 78 22 3a 30 2c 22 6e 61 6d 65 22 3a  index":0,"name":
#  22 6d 61 69 6e 22 2c 22 74 79 70 65 22 3a 22 76  "main","type":"v
#  6f 69 64 22 2c 22 76 61 6c 75 65 22 3a 22 30 40  oid","value":"0@
#  30 22 2c 22 65 6f 6c 22 3a 31 7d 5d 7d 0a        0","eol":1}]}.
#  01 00                                            ..
# --
