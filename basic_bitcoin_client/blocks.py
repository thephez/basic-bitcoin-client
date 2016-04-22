import logging
from binascii import hexlify, unhexlify
import struct
from lib.util import *
import time
from cStringIO import StringIO
from lib.database import *
from basic_bitcoin_client.transactions import *

logger = logging.getLogger()

class Blocks():
    def __init__(self):
        pass


    def parseblock(self, blockdata):
        '''
        Parse block data to get version, hashes, etc. and return info as dict along with the Tx Data separately
        :param blockdata:
        :return:
        '''
        #logger.info('Blockdata: {}'.format(hexlify(blockdata))) #!!!!!!! Remove later
        blockinfo = {}
        utility = Util()

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

        blockinfo['length'] = blockdata['length']

        decodeData = StringIO(blockdata['payload'])

        blockinfo['version'] = struct.unpack('<I', decodeData.read(4))[0]
        blockinfo['prevhash'] = hexlify(decodeData.read(32)[::-1])
        blockinfo['merkleroot'] = hexlify(decodeData.read(32)[::-1])
        timestamp = struct.unpack('<I', decodeData.read(4))[0]
        blockinfo['timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(timestamp))
        blockinfo['difficulty'] = struct.unpack('<I', decodeData.read(4))[0]
        blockinfo['nonce'] = struct.unpack('<I', decodeData.read(4))[0]
        blockinfo['txcount'] = utility.deserialize_int(decodeData)[0]

        txdata = decodeData.read()

        logger.info('Block Info\n\tVersion: {}\n\t'
                    'Previous Hash: {}\n\t'
                    'Merkle Root:{}\n\t'
                    'Timestamp: {}\n\t'
                    'Difficulty (hex): {:x}\n\t'
                    'Nonce: {}\n\t'
                    'Transaction Count: {}'.format(blockinfo['version'],
                                                      blockinfo['prevhash'],
                                                      blockinfo['merkleroot'],
                                                      blockinfo['timestamp'],
                                                      blockinfo['difficulty'],
                                                      blockinfo['nonce'],
                                                      blockinfo['txcount']))

        self.logblockdata(blockinfo)

        return blockinfo, txdata


    def logblockdata(self, blockinfo):
        '''
        Write block header info (version, hashes, etc.) to blocks table in database

        :param blockinfo:
        :return:
        '''
        db = MyDB('blockchain')
        db.insert('blocks',
                  'version, '
                  'hash_prev, '
                  'hash_merkle, '
                  'time, '
                  'difficulty, '
                  'nonce, '
                  'size, '
                  'tx_count', '\'{}\',\'{}\',\'{}\',\'{}\',\'{}\',\'{}\',\'{}\',\'{}\''.format(blockinfo['version'],
                                          blockinfo['prevhash'],
                                          blockinfo['merkleroot'],
                                          blockinfo['timestamp'],
                                          blockinfo['difficulty'],
                                          blockinfo['nonce'],
                                          blockinfo['length'],
                                          blockinfo['txcount']
                                          )
                  )
        return

if __name__ == '__main__':

    # Enable logging if running file directly
    logging.basicConfig(format='%(asctime)s:%(levelname)s:%(module)s:%(funcName)s:%(message)s', level=logging.INFO)
    blk = Blocks()
    tx = Transactions()


    blockinfo, txdata = blk.parseblock(msg)
    print(hexlify(msg['payload']))

    tx.parsetx(txdata, blockinfo['txcount'])
