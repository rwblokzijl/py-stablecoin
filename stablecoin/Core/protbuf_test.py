import Core.trustchain_pb2 as trustchain

if __name__ == '__main__':
    block = trustchain.Block()
    block.timestamp = 123
    block.sequence_no = 1
    block.ID.append(b"ASDFASDFASDF")
    henk = block.ID
    block.payload = b'321'

    print(block)
    waardes = block.SerializeToString()
    print(waardes, '\n')
    anderblock = trustchain.Block()
    anderblock.ParseFromString(waardes)
    print(anderblock)
