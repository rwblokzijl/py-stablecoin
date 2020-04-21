#!/usr/bin/env pipenv-shebang

import Core.trustchain_pb2 as trustchain_pb2
from gevent import pool
from gevent.server import StreamServer
import gevent.socket
import select
import subprocess
import sys
import argparse


def send_msg(sock, msg):
    # Prefix each message with a 4-byte length (network byte order)
    msg = len(msg).to_bytes(4, byteorder="big") + msg
    sock.sendall(msg)


def recv_msg(sock):
    # Read message length and unpack it into an integer
    raw_msglen = _recv_all(sock, 4)
    if not raw_msglen:
        return None
    msglen = int.from_bytes(raw_msglen, byteorder="big")
    # Read the message data
    return _recv_all(sock, msglen)


def _recv_all(sock, n):
    # Helper function to recv n bytes or return None if EOF is hit
    data = b''
    while len(data) < n:
        if select.select([sock], [], [], 1)[0]:
            packet = sock.recv(n - len(data))
            if len(packet) == 0:
                return None
        data += packet
    return data


class Rendezvous_Servic:
    def __init__(self, myIP = "127.0.0.1"):
        self.nodeList = trustchain_pb2.Nodelist()
        self.myIP = myIP
        self.server = None

    def run(self, Nonblocking = False):
        print("Starting rendevousz service")
        server_pool = pool.Pool(None)
        self.server = StreamServer(('0.0.0.0', 4321), self.message_handler, spawn=server_pool)
        if Nonblocking:
            self.server.start()
        else:
            self.server.serve_forever()

    def message_handler(self, socket, addres):
        while True:
            inputready, outputready, exceptready = select.select([socket], [], [], 0.1)
            if inputready:
                data = recv_msg(socket)
                if not data:
                    socket.close()
                    break
                if data[:1] == b"\xf0":
                    socket.shutdown(gevent.socket.SHUT_WR)
                    received_node = trustchain_pb2.Node()
                    received_node.ParseFromString(data[1:])
                    if addres[0] == "127.0.0.1":
                        received_node.IP = self.myIP
                    else:
                        received_node.IP = addres[0]
                    self.nodeList.nodes.add().CopyFrom(received_node)
                    print("{} connected from {}".format(received_node.friendlyName, received_node.IP))
            else:
                print("Tiny master timeout, but that's oke ;)")
                socket.close()
                break
        self.send_peerlist()

    def send_peerlist(self):
        serialized_nodelist = self.nodeList.SerializeToString()
        for node in self.nodeList.nodes:
            socket = gevent.socket.create_connection((node.IP, node.port))
            send_msg(socket, b'\xf2' + serialized_nodelist)
            socket.shutdown(gevent.socket.SHUT_RDWR)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Proof-of-Concept: Self-sovereign  banking.')
    parser.add_argument('--IP', nargs='?',metavar="ip", default='127.0.0.1',
            help="The internal ip of this machine, this will be used to " +
            "replace 127.0.0.1 with on incomming calls. (default = 127.0.0.1)")
    parser.add_argument('--dummyNodes', nargs='?', metavar='count', type=int,
            default=0, help='Number of extra nodes, which can only be witnesses')
    args = parser.parse_args()

    meeting_point = Rendezvous_Servic(myIP=args.IP)
    meeting_point.run(Nonblocking=True)

    processes = []
    # processes.append(subprocess.Popen(sys.executable + ' .\\Client.py --rendezvousPoint 127.0.0.1:4321 --name "My sovereign account" --guiPort 80 --log text.html'))
    for i in range(0, args.dummyNodes):
        processes.append(subprocess.Popen(sys.executable + ' Client.py --rendezvousPoint 127.0.0.1:4321 --name "Super smooth node no. {}" --port {}'.format(i,1964 +  i),shell=True))

    print("Rendezvous service up and running")
    print(meeting_point.server.address)
    while True:
        gevent.sleep(10)
