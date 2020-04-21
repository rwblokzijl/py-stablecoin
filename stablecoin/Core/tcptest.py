import gevent.socket as socket
import select
import threading
from gevent.server import StreamServer


class test_Client():
	def __init__(self, port):
		self.port = port
		print("Opening port at {}".format(port))


	def handle(self, socket, address):
		if select.select([socket], [], [], 10)[0]:
			data, addr = socket.recvfrom(1024)  # buffer size is 1024 bytes
			print(data)
			socket.send(b"HOI!\n")
			socket.close()

	def Run(self):
		print("Starting server")
		self.server = StreamServer(('127.0.0.1', self.port), self.handle)
		self.server.serve_forever()

if __name__ == "__main__":
	alice = test_Client(1963)
	bob = test_Client(1964)

	t_alice = threading.Thread(target=alice.Run)
	t_alice.start()

	t_bob = threading.Thread(target=bob.Run)
	t_bob.start()

	sok = socket.create_connection(("127.0.0.1", 1963), source_address=("192.168.178.1", 1964))
	sok.send(b"g")
	if select.select([sok], [], [], 10)[0]:
		data, addr = sok.recvfrom(1024)  # buffer size is 1024 bytes
		print(data)





# from Core.trustchain import TrustChain
# from nacl import signing
#
# if __name__ == "__main__":
# 	signing_key = signing.SigningKey.generate()
# 	trustchain = TrustChain(signing_key)