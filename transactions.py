from __future__ import division
import logging
from binascii import hexlify, unhexlify
import struct
import util
import time
from cStringIO import StringIO
import database
import os
import sys
import pprint

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

        txinfo = []
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

        decodeData = StringIO(txdata)

        # Get length of data, then reset to start
        decodeData.seek(0, os.SEEK_END)
        txdatalen = decodeData.tell()
        decodeData.seek(0)
        logger.info('Tx Data Length: {}'.format(txdatalen))

        # Loop through each transaction
        for txnum in range(1, txcount + 1):
            txdetails = {}
            logger.debug('Processing Tx # {}'.format(txnum))

            txdetails['version'] = struct.unpack('<I', decodeData.read(4))[0]
            txdetails['tx_in_count'] = utility.deserialize_int(decodeData)[0]
            txdetails['Number'] = txnum

            # Loop through each input
            logger.debug('Tx In Count: {}'.format(txdetails['tx_in_count']))
            for tx_input in range(txdetails['tx_in_count']):
                logger.debug('Tx In {}'.format(tx_input))
                logger.debug('Remaining length: {}'.format(txdatalen - decodeData.tell()))
                txdetails['input_prev_hash_{}'.format(tx_input)] = hexlify(decodeData.read(32)[::-1])
                txdetails['input_prev_index_{}'.format(tx_input)] = struct.unpack('<I', decodeData.read(4))[0]
                txdetails['input_script_length_{}'.format(tx_input)] = utility.deserialize_int(decodeData)[0]
                txdetails['input_script_{}'.format(tx_input)] = hexlify(decodeData.read(txdetails['input_script_length_{}'.format(tx_input)]))

                # Parse input script
                self.parsetxinputscript(txnum, tx_input, txinfo, txdetails)

                txdetails['input_sequence_{}'.format(tx_input)] = struct.unpack('<I', decodeData.read(4))[0]

            txdetails['tx_out_count'] = utility.deserialize_int(decodeData)[0]

            # Loop through each output
            logger.debug('Tx Out Count: {}'.format(txdetails['tx_out_count']))
            for tx_output in range(txdetails['tx_out_count']):
                txdetails['output_value_{}'.format(tx_output)] = struct.unpack('<q', decodeData.read(8))[0] # In Satoshis
                txdetails['output_value_{}'.format(tx_output)] = (txdetails['output_value_{}'.format(tx_output)] / 10**8) #value = (value / 10**8)
                txdetails['output_script_length_{}'.format(tx_output)] = utility.deserialize_int(decodeData)[0]
                txdetails['output_script_{}'.format(tx_output)] = hexlify(decodeData.read(txdetails['output_script_length_{}'.format(tx_output)]))

                # Parse out Opcodes, etc

            txdetails['lock_time'] = struct.unpack('<I', decodeData.read(4))[0]
            txinfo.append(txdetails)

        logger.info(pprint.pformat(txinfo))

        return txinfo

    def parsetxinputscript(self, txnum, tx_input, txinfo, txdetails):

            if txdetails['input_prev_hash_{}'.format(tx_input)] == '0000000000000000000000000000000000000000000000000000000000000000':
                logger.info('Coinbase Tx detected')
                logger.warning(txdetails)
                script_sig_pubkey_len = txdetails['input_script_length_{}'.format(tx_input)]
                #logger.warning('{}.\tscriptSig pubkey length: {}'.format(tx_input, txdetails['input_script_{}'.format(tx_input)][0:2]))
                logger.info('{}.\tscriptSig pubkey length: {}'.format(txnum, script_sig_pubkey_len))

                script_sig_data = txdetails['input_script_{}'.format(tx_input)]
                logger.warning('{}.\tCoinbase Script Data: {}\n'.format(txnum, script_sig_data))

            else:
                try:
                    script_sig_pubkey_len = int('0x' + str(txdetails['input_script_{}'.format(tx_input)][0:2]), 16) * 2
                    #logger.warning('{}.\tscriptSig pubkey length: {}'.format(tx_input, txdetails['input_script_{}'.format(tx_input)][0:2]))
                    script_sig_remaining_len = (txdetails['input_script_length_{}'.format(tx_input)] * 2) - script_sig_pubkey_len - 2 # 1 byte indicate length
                    logger.debug('{}.\tscriptSig pubkey length: {} (bytes) ({} bytes remaining)'.format(txnum, script_sig_pubkey_len, script_sig_remaining_len))

                    script_sig_data = txdetails['input_script_{}'.format(tx_input)][0 + 2:script_sig_pubkey_len + 2]
                    script_sig_remaining_len -= 2
                    logger.info('{}.\tscriptSig Data ({} bytes): {}'.format(txnum, script_sig_pubkey_len, script_sig_data))

                    if script_sig_remaining_len > 0:
                        script_sig_pubkeyhash_len = int('0x' + str(txdetails['input_script_{}'.format(tx_input)][script_sig_pubkey_len + 2:script_sig_pubkey_len + 4]), 16) * 2
                        logger.debug('{}.\tscriptSig pubkey hash length: {} (bytes)'.format(txnum, script_sig_pubkeyhash_len))
                        script_sig_pubkeyhash = txdetails['input_script_{}'.format(tx_input)][script_sig_pubkey_len + 4:script_sig_pubkey_len + 4 + script_sig_pubkeyhash_len]
                        logger.info('{}.\tScript Public Key Hash ({} bytes): {}\n'.format(txnum, script_sig_pubkeyhash_len, script_sig_pubkeyhash))
                    else:
                        logger.warning('{}.\t!!!!!!!!!!!!!! Single scriptSig parameter found!!!!!!!!!!!\n'.format(txnum))

                except Exception as e:
                    logger.error(txinfo[txnum-2])
                    logger.error('0x' + str(txdetails['input_script_{}'.format(tx_input)]))#[script_sig_pubkey_len + 2:script_sig_pubkey_len + 4]))
                    logger.error('{}.\tError processing: {}'.format(txnum, txdetails))
                    logger.error(e)
                    raise

if __name__ == '__main__':

    # Enable logging if running file directly
    logging.basicConfig(format='%(asctime)s:%(levelname)s:%(module)s:%(funcName)s:%(message)s', level=logging.DEBUG)
    tx = Transactions()

    # Partial block (#396853) for testing.  Truncated payload (only have first few Txs)
    msg = ''
    tx.parsetx(msg)