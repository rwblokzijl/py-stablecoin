"""
This will be a test with a consensus-less implementation of trustchain. One 'normal' implementation, and one with
half-blocks. The goal of this experiment is to determine if the half-block implementation indeeds performs worse.

Genesis block:
| 0x00 | Timestamp | creator ID | Signature | Hash |
    1   +  4 bytes  +  32 bytes  +  64 bytes + 32 bytes =  133

Transaction block:
| 0x01 | Timestamp | ID_1 | prev. hash | ID_2 | prev.hash | Value | Balance_1 | Balance_2 | Sign_1 | Sign_2 | Hash |
    1  + 4 bytes   + 32   +  32 bytes  +  32   + 32 bytes +   4   +  4 bytes  +  4 bytes  +   64   +   64   +  32   = 305

All ID's are edDSA25519 public keys. This can be easily converted to Curve25519 public keys if encryption is required
later on.

"""

import time
import Core.trustchain_pb2 as trustchain_pb2
from google.protobuf import message as pbMessage

from nacl import signing
import nacl.hash
import nacl.encoding


class TrustChain:

    def __init__(self, signing_key: signing.SigningKey):
        self.signing_key = signing_key
        self.last_hash = 0
        self.last_sequence_no = 0
        self.chain = {}

    def CreateBlock(self, payload, partner_ids: list):
        block = trustchain_pb2.Block
        block.timestamp = round(time.time())

        # todo: ask consensus module to pick witnesses
        IDs = [(bytes(self.signing_key.verify_key))] + partner_ids

        block.ID[:] = IDs
        block.previousHash[:] = [self.last_hash]
        block.sequence_no[:] = [self.last_sequence_no]

        block.payload = payload

    def create_genesis_block(self):
        '''
        Genesis block:
        | 0x00 | Timestamp | creator ID | Signature | Hash |
            1  +  4 bytes  +  32 bytes  +  64 bytes +  32  =  133
        '''
        ID = bytes(self.signing_key.verify_key)
        block = trustchain_pb2.Block()
        # create empty transaction
        transaction = trustchain_pb2.Transaction()
        transaction.timestamp = 0
        transaction.value = 0
        transaction.ID.append(ID)
        transaction.previousHash.append(b'\0')
        transaction.sequence_no.append(0)
        transaction.balance.append(1000)

        block.transaction = transaction.SerializeToString()
        block.signatures.append(self.signing_key.sign(block.transaction).signature)
        serial_block = block.SerializeToString()
        hash = nacl.hash.sha256(serial_block, encoder=nacl.encoding.RawEncoder)
        return serial_block + hash

    def hash_block(self, block):
        serial_block = block.SerializeToString()
        hash = nacl.hash.sha256(serial_block, encoder=nacl.encoding.RawEncoder)
        return serial_block + hash

    @staticmethod
    def verify_block(block_bytes):
        hash = block_bytes[-32:]
        block_bytes = block_bytes[:-32]

        if hash != nacl.hash.sha256(block_bytes, encoder=nacl.encoding.RawEncoder):
            raise ValueError("Hashes do not match")
        block = trustchain_pb2.Block()
        block.ParseFromString(block_bytes)

        transaction = trustchain_pb2.Transaction()
        transaction.ParseFromString(block.transaction)

        if len(transaction.ID) != len(block.signatures):
            print(transaction)
            print(block)
            raise ValueError("Number of signatures don't match with the number of ID's")

        for i in range(0, len(transaction.ID)):
            try:
                verify_key = nacl.signing.VerifyKey(transaction.ID[i])
                verify_key.verify(block.transaction, block.signatures[i])
            except nacl.exceptions.BadSignatureError as e:
                raise ValueError(e)

        if round(time.time()) < transaction.timestamp:
            raise ValueError("Block claims to be created in the future. current time {}, creation time {}".format(
                time.strftime("%Y-%m-%d %H:%M:%S", (time.gmtime())),
                time.strftime("%Y-%m-%d %H:%M:%S", (time.gmtime(transaction.timestamp)))))

        if transaction.value == 0:
            # Transaction is genesis block
            pass

        return block, hash

    @staticmethod
    def verify_witness_reply(transaction, aproval):
        if type(aproval) is bytes:
            try:
                received_approval = trustchain_pb2.Approval()
                received_approval.ParseFromString(aproval)
            except pbMessage.Error as e:
                raise ValueError("Message could not be interpreted as valid witness reply")
        else:
            received_approval = aproval

        verify_key = nacl.signing.VerifyKey(bytes(received_approval.ID))
        try:
            verify_key.verify(transaction, received_approval.signature)
        except nacl.exceptions.BadSignatureError:
            raise ValueError("Signature not valid!")
        return received_approval


    def propose_tx_block(self, prev_hash_1, ID_2, prev_hash_2, value: int, balance_1, balance_2):
        '''
        Transaction proposal block:
        | 0x01 | Timestamp | ID_1 | prev. hash | ID_2 | prev.hash | Value | Balance_1 | Balance_2 | Sign_1 |
            1  + 4 bytes   +  32  +  32 bytes  +  32   + 32 bytes +   4   +  4 bytes  +  4 bytes  +   64   = 209
        '''

        timestamp = round(time.time()).to_bytes(4, 'little', signed=False)
        value = value.to_bytes(4, 'little', signed=True)
        balance_1 = balance_1.to_bytes(4, 'little', signed=False)
        balance_2 = balance_2.to_bytes(4, 'little', signed=False)
        ID = bytes(self.signing_key.verify_key)

        signable_message = b'\1' + timestamp + ID + prev_hash_1 + ID_2 + prev_hash_2 + value + balance_1 + balance_2
        sign_1 = self.signing_key.sign(signable_message).signature

        return signable_message + sign_1

    @staticmethod
    def verify_tx_proposal_block(block):
        if len(block) != 209:
            raise ValueError("Expected block of length 209, got block of length {}".format(len(block)))

        if block[0] != 1:
            raise ValueError("Expected 0x00 as first byte, got {} as first byte".format(block[0]))

        verify_key = nacl.signing.VerifyKey(block[5:37])
        signed_message = block[0:145]
        signature = block[145:]

        try:
            verify_key.verify(signed_message, signature)
        except nacl.exceptions.BadSignatureError as e:
            raise ValueError(e)

    @staticmethod
    def interpret_tx_proposal_block(block):
        interpreted_block ={}
        interpreted_block['timestamp'] = block[1:5]
        interpreted_block["id_1"] = block[5:37]
        interpreted_block["previous_hash_1"] = block[37:69]
        interpreted_block["id_2"]=  block[69:101]
        interpreted_block["previous_hash_2"] = block[101:133]
        interpreted_block["value"] = int().from_bytes(block[133:137], 'little', signed=True)
        interpreted_block["balance_1"] = int().from_bytes(block[137:141], 'little', signed=False)
        interpreted_block["balance_2"] = int().from_bytes(block[141:145], 'little', signed=False)
        return interpreted_block

    @staticmethod
    def interpret_tx_block(block):
        interpreted_block ={}
        interpreted_block['timestamp'] = block[1:5]
        interpreted_block["id_1"] = block[5:37]
        interpreted_block["previous_hash_1"] = block[37:69]
        interpreted_block["id_2"]=  block[69:101]
        interpreted_block["previous_hash_2"] = block[101:133]
        interpreted_block["value"] = int().from_bytes(block[133:137], 'little', signed=True)
        interpreted_block["balance_1"] = int().from_bytes(block[137:141], 'little', signed=False)
        interpreted_block["balance_2"] = int().from_bytes(block[141:145], 'little', signed=False)
        interpreted_block["sign_1"] = block[145:209]
        interpreted_block["sign_2"] = block[209:273]
        interpreted_block["hash"] = block[273:305]
        return interpreted_block

    @staticmethod
    def interpret_genesis_block(block):
        interpreted_block = {}
        interpreted_block['timestamp'] = block[1:5]
        interpreted_block['id'] = block[5:37]
        interpreted_block['signature'] = block[37:101]
        interpreted_block['hash'] = block[101:133]
        return interpreted_block

    def sign_proposal_block(self, block):
        sign_2 = self.signing_key.sign(block[:145]).signature
        hash = nacl.hash.sha256(block + sign_2, encoder=nacl.encoding.RawEncoder)
        return block + sign_2 + hash

