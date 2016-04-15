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
        #logger.info('Blockdata: {}'.format(blockdata))
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
    logging.basicConfig(format='%(asctime)s:%(levelname)s:%(module)s:%(funcName)s:%(message)s', level=logging.DEBUG)
    blk = Blocks()
    tx = Transactions()

    # Partial block (#396853) for testing.  Truncated payload (only have first few Txs)
    msg = {'checksum': '\x9f\xad\x14h', 'length': 999959, 'magic_number': '\xf9\xbe\xb4\xd9', 'command': 'block', 'payload': '\x04\x00\x00\x00^,$\x1a\x8eSS\x81\x8f\xd9\x0b\xf9\x91i\xd9\x17\xb5\xa2\xe1\x04\x11~b\x04\x00\x00\x00\x00\x00\x00\x00\x003\xcft\x8ai\xdd\xf3\x0c"\x1fH\xa8\xb6\x87\xa9\x8b\x8c\xdc\xaf\xe6.\xb5\xbd\x13\x97\xef\xa40\x82(\xf17\xfd\xaf\xb4V\xf0(\t\x18l<v\x89\xfd?\x0c\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xffd\x035\x0e\x06\xe4\xb8\x83\xe5\xbd\xa9\xe7\xa5\x9e\xe4\xbb\x99\xe9\xb1\xbcPz\x8c\x8a\x16\xc1\x02#P\xaf\xef\xba\x9bB2\x94\xcf\x80au\xdc;R;x\x14\x8c\x8e$\x057\xa4\x02\x00\x00\x00\xf0\x9f\x90\x9fMined by guohuangzhi\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x11\x1c\x0f\x00\x01\xa2\xc1\x9a\x98\x00\x00\x00\x00\x19v\xa9\x14\xc8%\xa1\xec\xf2\xa6\x83\x0cD\x01b\x0c:\x16\xf1\x99PW\xc2\xab\x88\xac\x10\xdca4\x01\x00\x00\x00\x01\xd5\xc0\xe2\x84\xd1\xf3\x9a\xeb\x11\xc8\xcc~&\x1a\xf6\xd6M\xae\xc4\xdc\x0f\x1a\x90\xc3\xea\x83NR\xbdK,$\x01\x00\x00\x00jG0D\x02 i\x06\xf3j\x02\x84\xf6y\xe8\xee,/\xdb\xc7A}\xf3z\x8c\x02\x0e\xbf\x14p\xff\x991\x8eY)|&\x02 w?\xfd\x86c\xdb\xb1B\xb9\x06W\x8c\x1a\xd7\x7f\x84\xfd_t\x8e\x837\xc4>\xa3D\xf4\xfb\xbf\xa1n\xc1\x01!\x02\xb4xh\xfd\xd2\xf3\t%\x14\xe3S\x9f\x0f\xe6\xa8P*\xde\x98|\xb7\xf9\xb4\xa8\x96\x01\xa1\xc9+1\xb7\xac\xff\xff\xff\xff\x02 \xa1\x07\x00\x00\x00\x00\x00\x19v\xa9\x14>\xb98:K\xd2\xaa4\xc7\xec\x985\x02\x16L\xdc\x9f\xfc\x90\xff\x88\xac\x10(\x1c\x00\x00\x00\x00\x00\x19v\xa9\x14\xe6K\xa6\xd9T`#\xfd\xb6\x1eOeEej3/\xf0\x12)\x88\xac\x00\x00\x00\x00'}
    blockinfo, txdata = blk.parseblock(msg)
    print(hexlify(msg['payload']))