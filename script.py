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


class Script():
    def __init__(self):
        pass

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


    def parsetxoutputscript(self, txnum, tx_output, txinfo, txdetails):
        import opcodes

        try:
            for b1, b2 in zip(txdetails['output_script_{}'.format(tx_output)][0::2], txdetails['output_script_{}'.format(tx_output)][1::2]):
                #print('{}{}'.format(b1, b2))
                try:
                    opcode = int('{}{}'.format(b1, b2), 16)
                    opcodename = opcodes.get_opcode_name(opcode)
                    if ((opcodename != 'OP_INVALIDOPCODE' and opcodename != 'N/A')): logger.info('{} ({})\t{}'.format(hex(opcode), opcode, opcodename))
                except:
                    raise


            script_pubkey_len = int('0x' + str(txdetails['output_script_{}'.format(tx_output)][0:2]), 16) * 2
            #logger.warning('{}.\tscriptSig pubkey length: {}'.format(tx_input, txdetails['input_script_{}'.format(tx_input)][0:2]))
            script_pubkey_remaining_len = (txdetails['output_script_length_{}'.format(tx_output)] * 2) - script_pubkey_len - 2 # 1 byte indicate length
            logger.info(str(txdetails['output_script_{}'.format(tx_output)]))
            logger.info('{}.\toutput script pubkey length: {} (bytes) ({} bytes remaining)'.format(txnum, script_pubkey_len, script_pubkey_remaining_len))

        except Exception as e:
            #logger.error(txinfo[txnum-2])
            logger.error('0x' + str(txdetails['output_script_{}'.format(tx_output)]))#[script_sig_pubkey_len + 2:script_sig_pubkey_len + 4]))
            logger.error('{}.\tError processing output script of: {}'.format(txnum, txdetails))
            logger.error(e)
            raise

