import logging
from binascii import hexlify, unhexlify
import struct

logger = logging.getLogger()

class Blocks():
    def __init__(self):
        pass


    def parseblock(self, blockdata):
        #logger.info('Blockdata: {}'.format(blockdata))
        block = {}

        '''
        [---BLOCK_PAYLOAD---]
        [ 4] VERSION                <I                                  uint32_t
        [32] PREV_BLOCK_HASH                                            char[32]
        [32] MERKLE_ROOT                                                char[32]
        [ 4] TIMESTAMP              <I                                  uint32_t
        [ 4] BITS                   <I                                  uint32_t
        [ 4] NONCE                  <I                                  uint32_t
        [..] TX_COUNT               variable integer
        [..] TX                     multiple of TX_COUNT
            [..] TX                 see TX_PAYLOAD
        '''

        block['version'] = hexlify(blockdata['payload'][0:4])
        prevhash = hexlify(blockdata['payload'][35:3:-1])
        merkleroot = hexlify(blockdata['payload'][67:35:-1])
        timestamp = hexlify(blockdata['payload'][68:72])
        bits = struct.unpack('<I', blockdata['payload'][72:76])[0]
        nonce = struct.unpack('<I', blockdata['payload'][76:80])[0]
        #varint
        txcount = struct.unpack('<I', blockdata['payload'][80:84])[0]     #hexlify(blockdata['payload'][80:82])

        txmultiple = hexlify(blockdata['payload'][82:84])

        logger.info('\nVersion: {}\nPrevious Hash: {}\nMerkle Root:{}\nTimestamp: {}\nBits/Diff (hex): {:x}\nNonce: {}\nTransaction Count: {}\nTransaction Multiple: {}'.format(block['version'], prevhash, merkleroot, timestamp, bits, nonce, txcount, txmultiple))

        pass