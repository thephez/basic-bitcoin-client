from __future__ import division
import logging
from binascii import hexlify, unhexlify
import struct
import util
import time
from cStringIO import StringIO
import database
import os

logger = logging.getLogger()

class Transactions():
    def __init__(self):
        pass


    def parsetx(self, txdata, txcount):
        '''
        Parse Tx data to get version, hashes, etc.
        :param txdata:
        :return:
        '''

        txinfo = {}
        utility = util.Util()

        '''
        [---TX_PAYLOAD---]
        [ 4] VERSION                <I                                  uint32_t
        [..] TX_IN_COUNT            variable integer
        [..] TX_IN                  multiple of TX_IN_COUNT
            [32] PREV_OUT_HASH                                          char[32]
            [ 4] PREV_OUT_INDEX     <I (zero-based)                     uint32_t
            [..] SCRIPT_LENGTH      variable integer
            [..] SCRIPT             variable string
            [ 4] SEQUENCE           <I                                  uint32_t
        [..] TX_OUT_COUNT           variable integer
        [..] TX_OUT                 multiple of TX_OUT_COUNT
            [ 8] VALUE              <q                                  int64_t
            [..] SCRIPT_LENGTH      variable integer
            [..] SCRIPT             variable string
        [ 4] LOCK_TIME              <I                                  uint32_t
        '''

        txdetails = {}
        decodeData = StringIO(txdata)

        # Get length of data, then reset to start
        decodeData.seek(0, os.SEEK_END)
        txdatalen = decodeData.tell()
        decodeData.seek(0)
        logger.info('Tx Data Length: {}'.format(txdatalen))

        # Loop through each transaction
        for txnum in range(1, txcount + 1):

            tx_in = {}
            tx_out = {}

            logger.info('Tx #: {}'.format(txnum))
            txinfo['version'] = struct.unpack('<I', decodeData.read(4))[0]
            txinfo['tx_in_count'] = utility.deserialize_int(decodeData)[0]
            txdetails['Number'] = txnum

            #print(txinfo)
            # Loop through each input
            for tx in range(txinfo['tx_in_count']):
                logger.info('Remaining length: {}'.format(txdatalen - decodeData.tell()))
                txdetails['input_prev_hash_{}'.format(tx)] = hexlify(decodeData.read(32)[::-1])
                txdetails['input_prev_index'] = struct.unpack('<I', decodeData.read(4))[0]
                txdetails['input_script_length'] = utility.deserialize_int(decodeData)[0]
                txdetails['input_script'] = hexlify(decodeData.read(txdetails['input_script_length']))
                txdetails['input_sequence'] = struct.unpack('<I', decodeData.read(4))[0]

                # Parse TX In
                #logger.info('Hash: {}\t'
                #      'Index: {}\t'
                #      'Script Length: {}\t'
                #      'Script: {}\t'
                #      'Sequence: {}'.format(txdetails['input_prev_hash_{}'.format(tx)], index, scriptlen, script, seq))
                #tx_in.append(txdetails)
                pass

            txinfo['tx_out_count'] = utility.deserialize_int(decodeData)[0]
            txdetails['tx_out_count'] = txinfo['tx_out_count']

            # Loop through each output
            for tx in range(txinfo['tx_out_count']):
                txdetails['output_value'] = struct.unpack('<q', decodeData.read(8))[0] # In Satoshis
                #value = value / 10**8
                txdetails['output_script_length'] = utility.deserialize_int(decodeData)[0]
                txdetails['output_script'] = hexlify(decodeData.read(txdetails['output_script_length']))

                #tx_out.append(txdetails)
                #logger.info('Value: {}\t'
                #      'Script Length: {}\t'
                #      'Script: {}'.format(value, scriptlen, script))

            txinfo['lock_time'] = struct.unpack('<I', decodeData.read(4))[0]
            txdetails['lock_time'] = txinfo['lock_time']

            print(txinfo)
            print(txdetails)
            logger.info('Tx Details: {}'.format(txdetails))

        return txinfo



if __name__ == '__main__':

    # Enable logging if running file directly
    logging.basicConfig(format='%(asctime)s:%(levelname)s:%(module)s:%(funcName)s:%(message)s', level=logging.DEBUG)
    tx = Transactions()

    # Partial block (#396853) for testing.  Truncated payload (only have first few Txs)
    msg = ''
    tx.parsetx(msg)