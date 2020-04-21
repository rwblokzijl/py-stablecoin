#!/usr/bin/env pipenv-shebang
# -*- coding: utf-8 -*-


import sys

from Core.trustchain import TrustChain
import Core.trustchain_pb2 as trustchain_pb2
from google.protobuf import message as pbMessage

from gevent.server import StreamServer
# import gevent.greenlet

import gevent
import gevent.socket
import gevent.lock
# import queue
import gevent.queue as queue
import nacl.hash
import math
from nacl import signing
import time, threading, random
# import select
import gevent.select as select
import gevent.event

# RESTapi imports
from flask import Flask, jsonify, request, send_from_directory
from flask_headers import headers
import base64
import argparse
import logging


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


class Client:
    def __init__(self, master_address=None, master_port=None, port=1963, id=None):
        self.witness_count = 0

        # Stuff required for fwsp
        self.required_Witnesses = 0
        self.workersRunning = True
        self.witness_requests = queue.Queue()
        self.fwsp_requests = queue.Queue(maxsize=1)
        self.fwsp_reply = gevent.event.AsyncResult()
        self.fwsp_no_sigs = 0
        self.witness_Replies = []

        self.id = id
        self.trade_refusal_count = 0

        self.transaction_mutex = gevent.lock.Semaphore()

        # List of all the nodes
        self.peerList = trustchain_pb2.Nodelist()
        # Dict to convert IDs to IP:port tuples
        self.addressList = {}
        # Dict to convert ID's to friendly name
        self.friendlyNameList = {}

        # Hacky bootstrapping method, everybody starts with 1000
        self.balance = 1000
        self.sequenceNo = 0

        # Session variables
        self.trade_value = 0
        self.counter_party = 0
        self.counter_party_prev_hash = 0
        self.counter_party_sequenceNo = 0
        self.counter_balance = 0
        self.counter_chain = []
        self.proposed_block = 0
        self.state = 0
        self.reset_session()

        # public curve key for the master
        if master_address and master_port:
            self.master_address = (master_address, master_port)
        else:
            self.master_address = None

        # create a dict to store all the blocks entry 0 holds the hash to first block -1 the hash for the last
        self.chain = {}

        # Create ID, trustchain instance and genesis block
        self.signing_key = signing.SigningKey.generate()
        self.verify_key = bytes(self.signing_key.verify_key)
        self.trustchain = TrustChain(self.signing_key)
        genesis_block = self.trustchain.create_genesis_block()

        # Store the genesis block, and point update first and last pointer
        self.chain[0] = genesis_block[-32:]
        self.chain[-1] = genesis_block[-32:]
        self.chain[genesis_block[-32:]] = genesis_block

        self.port = port
        self.server = None

        self.logFile = None
        self.log = []

    def reset_session(self):
        self.trade_value = 0
        self.counter_party = 0
        self.counter_party_prev_hash = 0
        self.counter_party_sequenceNo = 0
        self.counter_balance = 0
        self.counter_chain = []
        self.proposed_block = 0
        self.fwsp_reply = gevent.event.AsyncResult()
        self.state = 0

    def run_random_simulation(self, run_time, sleep_time):
        stop_time = time.time() + run_time
        while time.time() < stop_time:
            gevent.sleep(random.uniform(0.001, sleep_time/1000))
            counter_party = random.choice(list(self.addressList.keys()))
            try:
                self.start_transaction(counter_party)
                # self.log("Transaction done!")
            except ValueError:
                pass
        self.send_to_master("Node {} created {} blocks. got refused {} times. witness = {} transactions".format(self.id, len(self.chain)-2, self.trade_refusal_count, self.witness_count))

    def run_fixed_partner_simulation(self, run_time):
        stop_time = time.time() + run_time
        if int(self.id) % 2 == 1:   # Nodes with odd numbers will only accept incoming request, not initiate any request
            # Trap to keep non-initiating nodes in this function until done
            while time.time() < stop_time:
                gevent.sleep(1)
            self.send_to_master(
                "Node {} created {} blocks. got refused {} times. witness = {} transactions".format(self.id,
                    len(self.chain) - 2, self.trade_refusal_count, self.witness_count))
            return

        for key, value in self.friendlyNameList.items():
            if str(int(self.id) + 1) == value:
                partner = key
                break

        while time.time() < stop_time:
            self.start_transaction(partner, 0)


        self.send_to_master("Node {} created {} blocks. got refused {} times. witness = {} transactions".format(self.id, len(self.chain)-2, self.trade_refusal_count, self.witness_count))

    def start_simulation(self, run_time, sleep_time=None):
        if not sleep_time:
            gevent.spawn(self.run_fixed_partner_simulation, run_time)
        else:
            gevent.spawn(self.run_random_simulation, run_time, sleep_time)

    def validate_transaction(self, ID, transaction, block):
        # A function that checks if the current transaction is a valid successor of the block for this specific node
        hash = block[-32:]

        # Find the index of node in current transaction
        index = -1
        for i in range(0, len(transaction.ID)):
            if transaction.ID[i] == ID:
                index = i
                break
        if index == -1:
            raise ValueError("Node is not owner of this transaction")

        block, x = self.trustchain.verify_block(block)
        temp_transaction = trustchain_pb2.Transaction()
        temp_transaction.ParseFromString(block.transaction)

        if transaction.previousHash[index] != hash:
            raise ValueError("PreviousHash does not point to actual previous hash")

        # determine old balance
        for i in range(0, len(temp_transaction.ID)):
            if temp_transaction.ID[i] == transaction.ID[index]:
                previous_balance = temp_transaction.balance[i]

        for i in range(0, len(transaction.ID)):
            if transaction.balance[i] < 0:
                logging.error(transaction)
                raise ValueError("Negative balance detected:")

        # If index = 0, node is on the receiving side
        if index == 0:
            if transaction.balance[index] != previous_balance + transaction.value:
                logging.error(transaction)
                raise ValueError("Previous and current value do not match with new balance")
        # if index  == 1, node is on giving side
        elif index == 1:
            if transaction.balance[index] != previous_balance - transaction.value:
                logging.error(transaction)
                raise ValueError("Previous and current value do not match with new balance")

    def witness_transaction(self, TransactionProposal):
        reply = b"\x00" # Default to nack

        request = trustchain_pb2.SignatureRequest()
        request.ParseFromString(TransactionProposal)
        transaction = trustchain_pb2.Transaction()
        transaction.ParseFromString(request.transaction)
        logging.info("received witness request")

        if self.select_witness(request.transaction, request.witnessCount, ) != self.verify_key:
            logging.error("prescribed witness ID does not match my ID")
            return reply

        # do this check for every party associated with the transaction
        try:
            for j in range(0, len(transaction.ID)):
                self.validate_transaction(transaction.ID[j], transaction, request.chains[j].blocks[0])
        except ValueError as e:
            logging.exception("A problematic transaction was detected during witnessing \n")
            return reply

        signature = trustchain_pb2.Approval()
        signature.ID = self.verify_key
        signature.i = request.witnessCount
        signature.signature = self.signing_key.sign(request.transaction).signature
        reply = signature.SerializeToString()
        logging.info("Transaction ")
        return reply

    def get_signature(self, ith_witness, request, reply_queue):
        request.witnessCount = ith_witness
        serialized_request = request.SerializeToString()
        witness = self.select_witness(request.transaction, ith_witness)

        socket = gevent.socket.create_connection(self.addressList[witness])
        send_msg(socket, b'\x10' + serialized_request)
        try:
            if select.select([socket], [], [], 1)[0]:
                data = recv_msg(socket)
                if not data:
                    socket.close()
                else:

                    if data[:1] == b'\x11':
                        result = data[1:]
                        reply_queue.put(result)
                    socket.shutdown(gevent.socket.SHUT_RDWR)
            else:
                # self.log("signature collection handler timed out")
                socket.close()
                reply_queue.put(None)

        except (ConnectionAbortedError, ConnectionResetError) as e:
            reply_queue.put(None)

    def collect_signatures(self, request, witness_count, result, max_Witness=None):
        no_replies = 0
        if not max_Witness:
            max_Witness = self.required_Witnesses

        witness_Replies = queue.Queue()

        valid_signatures = []
        k = math.floor(2 * witness_count / 3) + 1
        logging.info("At least {} witnesses are required before the transaction will pass".format(k))
        greenlets = []
        for j in range(0, witness_count):
            greenlets.append(gevent.spawn(self.get_signature, j, request, witness_Replies))

        timeout = 5
        blocking = True
        while True:
            try:
                response = witness_Replies.get(block=blocking, timeout=timeout)   # Blocking call on purpose
                no_replies += 1

                # # if the respone is not bytes, the communication has failed
                # if not type(response) is bytes:
                #     continue
                #
                # if len(response) <= 1:
                #     logging.info("received Nack")
                #     continue

                if type(response) is bytes and len(response) > 1:
                    try:
                        valid_signatures.append(TrustChain.verify_witness_reply(request.transaction, response))
                        logging.info("Valid witness reply received.")
                    except ValueError:
                        logging.exception("Verification of the witness reply failed.")
                else:
                    logging.info("Received Nack on witness request.")
                # try:
                #     signature = trustchain_pb2.Approval()
                #     signature.ParseFromString(response)
                # except pbMessage.Error as e:
                #     logging.exception("An error occured in collect_signatures()\n")
                #     continue
                #
                # verify_key = nacl.signing.VerifyKey(bytes(signature.ID))
                # try:
                #     verify_key.verify(request.transaction, signature.signature)
                #     valid_signatures.append(response)
                # except nacl.exceptions.BadSignatureError:
                #     logging.exception("Error occured in collect_signatures() \n")
                #     continue

                if len(valid_signatures) >= k:
                    # By etting blocking to false instead of directly exiting gives the possibility to verify any
                    # remaining signatures and use them as well.
                    blocking = False

                elif no_replies == witness_count:
                    if witness_count == max_Witness:
                        logging.info("Max witnesses reached but not enough valid replies.")
                        # Since we've received all replies, and there is not enough, we can cancel directly
                        break
                    else:
                        logging.info("All witnesses replied, but nog enough are valid: Extending witness set")
                        for j in range(0, 3):
                            greenlets.append(gevent.spawn(self.get_signature, j, request, witness_Replies))

                        witness_count += 3
                        k = math.floor(2 * witness_count / 3)

            except queue.Empty:
                break
        result.set(valid_signatures)

        for greenlet in greenlets:
            greenlet.kill()
        return

    def select_witness(self, transaction, i):
        def gte(a, b):
            if a == b:
                return True
            for i in range(0, 31):
                if a[i] > b[i]:
                    return True
                if a[i] < b[i]:
                    return False
            return True

        hash = nacl.hash.sha256(transaction + i.to_bytes(4, byteorder='little', signed=True), encoder=nacl.encoding.RawEncoder)

        node_list = list(self.addressList.keys())

        node_list.append(self.verify_key)
        tx = trustchain_pb2.Transaction()
        tx.ParseFromString(transaction)
        for ID in tx.ID:
            try:
                node_list.remove(bytes(ID))
            except KeyError:
                pass

        node_list.sort()
        witness = node_list[0]
        for node in node_list:
            if gte(node, hash):
                return witness
            if gte(node, witness):
                witness = node
        return witness

    def send_to_master(self, payload):
        socket = gevent.socket.create_connection(self.master_address)
        send_msg(socket, b'\xf1' + payload.encode('utf-8'))
        if select.select([socket], [], [], 1)[0]:
            data = recv_msg(socket)
            socket.shutdown(gevent.socket.SHUT_RDWR)
            if not data:
                socket.close()
                self.state = 0
                return

    def log(self, text):
        return
        # payload = ("{} {} - {}: {}".format(time.time(), self.id, self.state, text))

    def message_handler(self, socket, address):
        if select.select([socket], [], [], 2)[0]:
            data = recv_msg(socket)
            # Not sure if this makes sense, question is, is this function called when the connection is started
            # or when data is send.
            if not data:
                socket.close()

            # Trade request
            elif data[:1] == b'\x01':
                # A new session may only begin if state == 0
                if not self.transaction_mutex.acquire(blocking=False):
                    send_msg(socket, b'\x00')
                    socket.close()
                    return
                else:
                    self.reset_session()
                    result = self.fsm(data)
                    send_msg(socket, result)

                # TODO: Understant this loop
                while True:
                    try:
                        if select.select([socket], [], [], 1)[0]:
                            data = recv_msg(socket)
                            if not data:
                                socket.close()
                                break
                            if data[:1] == b'\x00':
                                logging.info("Received nack: sending socket shutdown signal!")
                                try:
                                    socket.shutdown(gevent.socket.SHUT_RDWR)
                                except OSError as e:
                                    logging.exception("Error directly after receiving a nack\n")
                                    pass
                                break
                            result = self.fsm(data)

                            # When according to the fsm, nothing needs to be done,
                            if not result:
                                socket.shutdown(gevent.socket.SHUT_WR)
                            else:
                                send_msg(socket, result)
                        else:
                            # self.log("Message Handler Timed out")
                            logging.error("Message handler timed out")
                            socket.close()
                    except (ConnectionAbortedError, ConnectionResetError, ValueError, BrokenPipeError):
                        logging.exception("Connection error in message handler\n")
                        if not socket.closed:
                            socket.close()
                        break

                self.reset_session()
                self.transaction_mutex.release()

            # Signing request
            elif data[:1] == b"\x10":
                self.witness_count += 1
                result = b"\x11" + self.witness_transaction(data[1:])
                send_msg(socket, result)
                # ON debian it appaers that sending a shutdown mgith fail
                try:
                    socket.shutdown(gevent.socket.SHUT_RDWR)
                except OSError as e:
                    pass
            # Recieved peerlist
            elif data[:1] == b"\xf2":
                self.importPeerlist(data[1:])

            ## I think all these funtions are for benchmarking, we dont have the benchmarking code ##
            # Randomized partner start
            elif data[:1] == b"\xf3":
                logging.info("received command to start random partner simulation")
                runtime = int.from_bytes(data[1:5], byteorder="little")
                sleeptime = int.from_bytes(data[5:10], byteorder="little")
                self.start_simulation(runtime, sleeptime)
            # Fixed_parter_Start
            elif data[:1] == b"\xf4":
                logging.info("received command to start fixed partner simulation")
                runtime = int.from_bytes(data[1:5], byteorder="little")
                self.start_simulation(runtime)
            # Shutdown
            elif data[:1] == b"\xff":
                logging.info("Received shutdown message.")
                self.reset_session()
                self.workersRunning = False
                self.server.stop()

        if not socket.closed:
            socket.close()

    def connect_to_master(self):
        peer = trustchain_pb2.Node()
        peer.friendlyName = self.id
        peer.ID = bytes(self.signing_key.verify_key)
        peer.IP = "127.0.0.1"
        peer.port = self.port
        print(self.master_address)

        # self.log("{} started: {}".format(self.id, peer.SerializeToString()))

        socket = gevent.socket.create_connection(self.master_address)
        send_msg(socket, b'\xf0' + peer.SerializeToString())
        if select.select([socket], [], [], 1)[0]:
            data = recv_msg(socket)
            if not data:
                socket.close()
                self.state = 0
                return
        else:
            logging.warning("Message Handler Timed out")
            socket.close()

    def Run(self):
        if self.master_address:
            self.connect_to_master()
        self.server = StreamServer(('0.0.0.0', self.port), self.message_handler)
        logging.info("Sarted server at port {}".format(self.port))
        self.server.serve_forever()

    def fsm(self, message):
        # # Statemachine implementation (See notes.pptx for diagram)
        # States for initiator node
        reply = b'\x00' # Always default to nack
        if self.state == 0:
            if message[:1] == b'\x01':
                trade_request = trustchain_pb2.TradeRequest()
                trade_request.ParseFromString(message[1:])

                self.counter_party = trade_request.publicKey
                self.trade_value = trade_request.value

                if self.counter_party not in self.addressList:
                    logging.warning("Incoming transaction from unknown id {}".format(self.counter_party))
                    return reply
                logging.info("Incoming transaction from {}".format(self.friendlyNameList[self.counter_party]))

                try:
                    counter_block, self.counter_party_prev_hash = self.trustchain.verify_block(trade_request.blocks[0])
                except ValueError:
                    logging.exception("Found invalid block in trade request")
                    return reply


                counter_transaction = trustchain_pb2.Transaction()
                counter_transaction.ParseFromString(counter_block.transaction)

                block_is_valid = False
                for i in range(0, len(counter_transaction.ID)):
                    if counter_transaction.ID[i] == self.counter_party:
                        self.counter_balance = counter_transaction.balance[i]
                        self.counter_party_sequenceNo = counter_transaction.sequence_no[i]
                        block_is_valid = True
                        break

                # Todo: re-enable balance check for normal usage
                if self.counter_balance < self.trade_value:
                    logging.warning("Value is more than balance! value is {}, received last block is: \n {} \n THIS WILL BE INGORED FOR DEMONSTRATION PURPOSES".format(self.trade_value ,str(counter_transaction)))
                    # return reply

                if block_is_valid:
                    transaction = trustchain_pb2.Transaction()
                    transaction.timestamp = round(time.time())

                    transaction.previousHash.append(self.chain[-1])
                    transaction.previousHash.append(self.counter_party_prev_hash)

                    transaction.sequence_no.append(self.sequenceNo + 1)
                    transaction.sequence_no.append(self.counter_party_sequenceNo + 1)

                    transaction.ID.append(bytes(self.signing_key.verify_key))
                    transaction.ID.append(self.counter_party)

                    transaction.value = self.trade_value

                    transaction.balance.append(self.balance + self.trade_value)
                    transaction.balance.append(self.counter_balance - self.trade_value)

                    # Create a block for the counter party to sign
                    block = trustchain_pb2.Block()
                    block.transaction = transaction.SerializeToString()
                    block.signatures.append(self.signing_key.sign(block.transaction).signature)
                    self.proposed_block = block

                    trade_reply = trustchain_pb2.TradeReply()
                    trade_reply.proposedBlock = block.SerializeToString()
                    trade_reply.blocks.append(self.chain[self.chain[-1]])

                    #  trade_ack, + last block
                    reply = b'\02' + trade_reply.SerializeToString()
                    self.state = 2
            return reply

        # Wait for trade reply
        if self.state == 1:
            if message[:1] == b"\x02":  # 2 is trade_reply
                trade_reply = trustchain_pb2.TradeReply()
                trade_reply.ParseFromString(message[1:])
                # Verify block
                try:
                    counter_block, self.counter_party_prev_hash = self.trustchain.verify_block(trade_reply.blocks[0])
                except ValueError:
                    return reply
                # todo: make the following code work for multiple blocks
                chain = trustchain_pb2.Chain()
                chain.blocks.append(self.chain[self.chain[-1]])

                counter_chain = trustchain_pb2.Chain()
                counter_chain.blocks.append(trade_reply.blocks[0])

                counter_transaction = trustchain_pb2.Transaction()
                counter_transaction.ParseFromString(counter_block.transaction)

                block_is_valid = False
                for i in range(0, len(counter_transaction.ID)):
                    if counter_transaction.ID[i] == self.counter_party:
                        self.counter_balance = counter_transaction.balance[i]
                        self.counter_party_sequenceNo = counter_transaction.sequence_no[i]
                        block_is_valid = True
                        break
                # shit down is copied from previous itteration
                try:
                    block = trustchain_pb2.Block()
                    block.ParseFromString(trade_reply.proposedBlock)

                    transaction = trustchain_pb2.Transaction()
                    transaction.ParseFromString(block.transaction)
                except ValueError as e:
                    print(e)
                    return reply

                if len(block.signatures) != 1:
                    print(transaction)
                    print(block)
                    raise ValueError("WTF, dit  block is helemaal niet getekend fucker")

                # Check if the values are actually the values you agreed uppon
                for i in range(0, len(transaction.ID)):
                    if self.trade_value != transaction.value:
                        raise ValueError("trade agreed on {}".format(self.trade_value))
                    # Checks for Counter party
                    if transaction.ID[i] == self.counter_party:
                        if self.counter_balance + self.trade_value != transaction.balance[i]:
                            block_is_valid = False
                            print(transaction)
                            print("Counter balance don't match old {}".format(self.counter_balance))
                        if self.counter_party_prev_hash != transaction.previousHash[i]:
                            block_is_valid = False
                            print(transaction)
                            print("Counter hash don't match {}".format(self.counter_party_prev_hash))
                        if self.counter_party_sequenceNo + 1!= transaction.sequence_no[i]:
                            block_is_valid = False
                            print(transaction)
                            print(" Counter sequence NO don't match {}".format(self.counter_party_sequenceNo))
                    # Checks for mine
                    if transaction.ID[i] == bytes(self.signing_key.verify_key):
                        if self.balance - self.trade_value != transaction.balance[i]:
                            block_is_valid = False
                            print(transaction)
                            print("my balance don't match old {}".format(self.balance))
                        if self.chain[-1][-32:] != transaction.previousHash[i]:
                            block_is_valid = False
                            print(transaction)
                            print("my hash don't match {}".format(self.chain[-1][-32:]))
                        if self.sequenceNo + 1 != transaction.sequence_no[i]:
                            block_is_valid = False
                            print(transaction)
                            print("My sequence NO don't match {}".format(self.sequenceNo))

                if block_is_valid:
                    block.signatures.append(self.signing_key.sign(block.transaction).signature)
                else:
                    return reply

                self.proposed_block = block
                if self.required_Witnesses > 0:
                    request = trustchain_pb2.SignatureRequest()
                    request.transaction = transaction.SerializeToString()

                    request.chains.add().CopyFrom(counter_chain)
                    request.chains.add().CopyFrom(chain)

                    gevent.spawn(self.collect_signatures, request, self.required_Witnesses, self.fwsp_reply)

                    try:
                        sigs = self.fwsp_reply.get(block=True, timeout=0.5)
                        if len(sigs) == 0:
                            logging.error("Transaction failed, not enough valid witnesses")
                            # print("Aaawh FWSP failed")
                            return reply
                    except gevent.timeout.Timeout:
                        logging.info("Sending keep alive message: not enough valid witness replies.")
                        reply = b'\x03' + self.fwsp_no_sigs.to_bytes(4,byteorder='big',signed=False)
                        self.state = 3
                        return reply

                    self.proposed_block.witnesses.extend(sigs)
                    logging.info("Transaction successful with {}/{} valid witness replies".format(len(sigs),
                                                                                              self.required_Witnesses))
                block_bytes = self.proposed_block .SerializeToString()
                block = block_bytes + nacl.hash.sha256(block_bytes, encoder=nacl.encoding.RawEncoder)

                self.chain[block[-32:]] = block
                self.chain[-1] = block[-32:]
                self.balance = self.balance - self.trade_value
                self.sequenceNo = self.sequenceNo + 1
                reply = b'\x05' + block
            return reply

        # Had to send keep alive message
        if self.state == 3:
            if message[:1] == b"\x04":
                try:
                    sigs = self.fwsp_reply.get(block=True, timeout=0.5)
                    if len(sigs) == 0:
                        logging.error("Transaction failed, not enough valid witnesses")
                        return reply
                except gevent.timeout.Timeout:
                    logging.info("Sending keep alive message: not enough valid witness replies.")
                    reply = b'\x03' + self.fwsp_no_sigs.to_bytes(4,byteorder='big',signed=False)
                    return reply

                self.proposed_block.witnesses.extend(sigs)
                logging.info("Transaction successful with {}/{} valid witness replies".format(len(sigs),
                                                                                              self.required_Witnesses))
                block_bytes = self.proposed_block.SerializeToString()
                block = block_bytes + nacl.hash.sha256(block_bytes, encoder=nacl.encoding.RawEncoder)

                self.chain[block[-32:]] = block
                self.chain[-1] = block[-32:]
                self.balance = self.balance - self.trade_value
                self.sequenceNo = self.sequenceNo + 1
                reply = b'\x05' + block
                return reply

        if self.state == 2:
            if message[:1] == b"\x05":
                block = message[1:]
                try:
                    received_block, hash = TrustChain.verify_block(block)
                except ValueError:
                    logging.exception("Malformed block received in final stage\n")
                    return reply

                if self.proposed_block.transaction != received_block.transaction:
                    logging.warning("Block does not contain transaction earlier agreed uppon")
                    return reply
                valid_witnesses = 0
                for aproval in received_block.witnesses:
                    try:
                        TrustChain.verify_witness_reply(received_block.transaction, aproval)
                        valid_witnesses += 1
                    except ValueError:
                        logging.exception("Error occured during the verification of witness replies in teh block")

                logging.info("Transaction successful with {}/{} witness".format(valid_witnesses, self.required_Witnesses))
                self.chain[block[-32:]] = block
                self.chain[-1] = block[-32:]
                self.balance = self.balance + self.trade_value
                self.sequenceNo = self.sequenceNo + 1
                reply = None
            elif message[:1] == b'\x03':
                logging.info("Received keep alive while waiting on signatures")
                reply = b"\x04"
            return reply

    def start_transaction(self, peerID, Value=-1):
        logging.info("Initiated transaction with {}, value: {}".format(self.friendlyNameList[peerID], Value))
        if peerID not in self.addressList:
            logging.error("Supplied ID not know by this node.")
            raise ValueError("Supplied ID not know by this node.")

        # if self.balance < 10:
        #     return

        if not self.transaction_mutex.acquire(blocking=False):
            self.trade_refusal_count += 1
            return

        self.reset_session()

        try:
            socket = gevent.socket.create_connection(self.addressList[peerID])
        except OSError as e:

            self.trade_refusal_count += 1
            self.transaction_mutex.release()
            logging.exception("Tried to connect to {} at{}, {}\n".format(self.friendlyNameList[peerID], *self.addressList[peerID]))
            return

        self.counter_party = peerID
        self.state = 1

        trade_request = trustchain_pb2.TradeRequest()
        trade_request.publicKey = bytes(self.signing_key.verify_key)

        if Value >= 0:
            self.trade_value = Value
        else:
            self.trade_value = random.randint(1, self.balance)

        trade_request.value = self.trade_value
        trade_request.blocks.append(self.chain[self.chain[-1]])
        message = b'\x01' + trade_request.SerializeToString()
        send_msg(socket, message)
        try:
            while True:
                    if select.select([socket], [], [], 20)[0]:
                        data = recv_msg(socket)
                        if not data:
                            socket.close()
                            break
                        if data == b'\00':
                            try:
                                socket.shutdown(gevent.socket.SHUT_WR)
                            except OSError as e:
                                pass
                        else:
                            reply = self.fsm(data)
                            if not reply:
                                socket.shutdown(gevent.socket.SHUT_WR)
                            else:
                                send_msg(socket, reply)
                                if reply[:1] == b'\x05':
                                    socket.shutdown(gevent.socket.SHUT_WR)
                    else:
                        # print("Start transaction Timed out")
                        logging.error("socket timed out in 'startTranscation()")
                        socket.close()
        except (ConnectionAbortedError, ConnectionResetError) as e: # gevent.socket.error,
            if not socket.closed:
                socket.close()
            pass
            # print("Hmm we experience : {}".format(e))

        self.reset_session()
        self.transaction_mutex.release()

    def importPeerlist(self, peerList_bytes):
        logging.info("Received updated peer list")
        self.peerList.ParseFromString(peerList_bytes)
        for peer in self.peerList.nodes:
            if peer.ID != bytes(self.signing_key.verify_key):
                if peer.IP == "127.0.0.1":
                    peer.IP = args.localhost
                self.addressList[peer.ID] = (peer.IP, peer.port)
                self.friendlyNameList[peer.ID] = str(peer.friendlyName)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Proof-of-Concept: Self-sovereign  banking.')
    parser.add_argument('--rendezvousPoint', nargs='?',metavar="ip:port", help="Address that will be used for peer discovery.")
    parser.add_argument('--name', nargs='?', metavar="name", help="Friendly name for the node.")
    parser.add_argument('--port', nargs='?', type=int, default=1963,
            help="Port on which the application will accept incomming connections (default = 1963).")
    parser.add_argument('--localhost', nargs='?', metavar="ip", default="127.0.0.1",
            help='Sets the loopback ip. usefull when running in containers (default = 127.0.0.1)')
    parser.add_argument('--requiredWitnessess', nargs='?', metavar='count', type=int, default=6,
            help='Number of witnesses required by FWSP(default = 6)')
    parser.add_argument('--guiPort', nargs="?", metavar="port",
            help="If set a web interface will be exposed at port specified port (default = None)")
    parser.add_argument('--log', nargs="?", metavar="file name", default=None,
            help="filename for the log. if set to 'memory' log will be available to REST-api but deleted on exit (default = memory)")

    args = parser.parse_args()
    if args.log == "memory":
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
    elif args.log:
        logging.basicConfig(filename="./Log/{}".format(args.log), level=logging.DEBUG,
                format='%(asctime)s: %(levelname)s - %(message)s <br>', datefmt='%m/%d/%Y %H:%M:%S')
    else:
        logging.basicConfig(level=logging.CRITICAL, format='%(asctime)s %(message)s',
                            datefmt='%m/%d/%Y %H:%M:%S')

    if args.rendezvousPoint:
        masterAddress = args.rendezvousPoint.split(':', 1)
        if masterAddress[0] == "127.0.0.1":
            masterAddress[0] = args.localhost
        if not masterAddress[1].isdigit():
            raise ValueError("Expected port number got {}".format(masterAddress[1]))
            quit()

        if not type(args.port) is int:
            raise ValueError("Expected port number got {}".format(masterAddress[1]))
            quit()
    else:
        masterAddress = (None, 0)


    logging.info("Starting {} at {} and will connect to ({},{})".format(args.name, args.port, masterAddress[0], int(masterAddress[1])))

    client = Client(masterAddress[0], int(masterAddress[1]), args.port, args.name)
    client.required_Witnesses = args.requiredWitnessess
    thread = threading.Thread(target=client.Run)

    if client.master_address:
        thread.start()

    if args.guiPort:
        app = Flask(__name__, static_url_path='')

        @app.route('/')
        @app.route('/index.html')
        @headers({'Cache-Control': "no-cache, no-store, must-revalidate", "Pragma": "no-cache", "Expires": "0"})
        def serve_index():
            if not client.master_address:
                return send_from_directory("./Web/", "setup.html"), 200
            else:
                return send_from_directory("./Web/", "index.html"), 200

        @app.route("/API/v0.1/log")
        @headers({'Cache-Control': "no-cache, no-store, must-revalidate", "Pragma": "no-cache", "Expires": "0"})
        def serve_log():
            if args.log and args.log != "memory":
                return send_from_directory("./Log/", args.log), 200
            else:
                return "Logs aren't written to file", 200


        @app.route('/API/v0.1/setup', methods=['POST'])
        def serve_setup():
            if client.master_address:
                return jsonify("Server is already setup"), 500
            if not (request.is_json):
                return jsonify("REquest has to be in JSON form transaction"), 500
            content = request.get_json()
            if not ("Address" in content and "FriendlyName" in content):
                return jsonify("Malformed transaction"), 500
            address = content["Address"].split(':', 1)
            if not address[1].isdigit():
                return jsonify("Malformed transaction"), 500
            if address[0] == "127.0.0.1":
                address[0] = args.localhost

            client.master_address = (address[0], address[1]) # this probably works as one
            client.id = content["FriendlyName"]
            thread.start()
            return jsonify("starting as {} and will connect to {}:{}".format(client.id, *client.master_address))


    # headers["Cache-Control"] = "no-cache, no-store, must-revalidate"  # HTTP 1.1.
    # headers["Pragma"] = "no-cache"  # HTTP 1.0.
    # headers["Expires"] = "0"  # Proxies.


        @app.route('/transactions.html')
        def serve_transactions():
            return send_from_directory("./Web/", "transactions.html"), 200

        @app.route('/API/v0.1/account')
        def balance():
            return jsonify({"Name": client.id, "Type": "Personal account (Demo)", "Address": base64.urlsafe_b64encode(client.verify_key).decode('UTF-8'), "balance": "{}".format(client.balance)}), 200, {'Access-Control-Allow-Origin': '*'}

        @app.route('/API/v0.1/partners')
        def partners():
            nodes = []
            for node in client.peerList.nodes:
                if node.ID != client.verify_key:
                    nodes.append((node.friendlyName, base64.urlsafe_b64encode(node.ID).decode('UTF-8')))
            return jsonify({"Nodes": nodes}), 200

        @app.route('/API/v0.1/startTransaction', methods=['POST'])
        def server_startTransaction():
            if not (request.is_json):
                return "No valid JSON"
            content = request.get_json()
            if not ("Recepient" in content and "Value" in content):
                return "Malformed transaction", 500
            counterParty = base64.urlsafe_b64decode(content["Recepient"].encode('UTF-8'))
            value = content["Value"]
            client.start_transaction(counterParty, value)
            return jsonify("Transaction received"), 200

        @app.route('/API/v0.1/transactions')
        def transactions():
            start = request.args.get('from')
            if not start or start == "":
                next = client.chain[-1]
            else:
                next = base64.urlsafe_b64decode(start.encode('UTF-8'))

            length = request.args.get('length')
            if not length:
                length = 25
            else:
                length = int(length)

            length = min(length, len(client.chain)-3)

            transactions = []
            for entries in range(length):
                block_bytes = client.chain[next][:-32]
                block = trustchain_pb2.Block()

                block.ParseFromString(block_bytes)
                transaction = trustchain_pb2.Transaction()
                transaction.ParseFromString(block.transaction)
                myID = None
                for i in range(len(transaction.ID)):
                    if transaction.ID[i] == bytes(client.verify_key):
                        myID = i
                if myID == 1:
                    value = transaction.value * -1
                else:
                    value = transaction.value
                next = transaction.previousHash[myID]
                transactions.append(((time.strftime("%b %d %Y %H:%M:%S",
                    time.gmtime(transaction.timestamp))),
                    client.friendlyNameList[transaction.ID[1-myID]], "EUR {0:.2f}".format(value), base64.urlsafe_b64encode(next).decode('UTF-8')))

                if next == b'\x00':
                    break

            return jsonify({"from": base64.urlsafe_b64encode(next).decode('UTF-8'), "transactions": transactions}), 200, {'Access-Control-Allow-Origin': '*'}

        # Disable the webserver logging for demo purposes
        logging.getLogger('werkzeug').setLevel(logging.ERROR)
        app.run(host='0.0.0.0', port=args.guiPort, debug=False, threaded=True)

