#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# protocol.py - Bitcoin protocol access for Bitnodes.
#
# Copyright (c) Addy Yeow Chin Heng <ayeowch@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

"""
Bitcoin protocol access for Bitnodes.
Reference: https://en.bitcoin.it/wiki/Protocol_specification

-------------------------------------------------------------------------------
                     PACKET STRUCTURE FOR BITCOIN PROTOCOL
                           protocol version >= 70001
-------------------------------------------------------------------------------
[---MESSAGE---]
[ 4] MAGIC_NUMBER               (\xF9\xBE\xB4\xD9)                  uint32_t
[12] COMMAND                                                        char[12]
[ 4] LENGTH                     <I (len(payload))                   uint32_t
[ 4] CHECKSUM                   (sha256(sha256(payload))[:4])       uint32_t
[..] PAYLOAD                    see below

    [---VERSION_PAYLOAD---]
    [ 4] VERSION                <i                                  int32_t
    [ 8] SERVICES               <Q                                  uint64_t
    [ 8] TIMESTAMP              <q                                  int64_t
    [26] ADDR_RECV
        [ 8] SERVICES           <Q                                  uint64_t
        [16] IP_ADDR
            [12] IPV6           (\x00 * 10 + \xFF * 2)              char[12]
            [ 4] IPV4                                               char[4]
        [ 2] PORT               >H                                  uint16_t
    [26] ADDR_FROM
        [ 8] SERVICES           <Q                                  uint64_t
        [16] IP_ADDR
            [12] IPV6           (\x00 * 10 + \xFF * 2)              char[12]
            [ 4] IPV4                                               char[4]
        [ 2] PORT               >H                                  uint16_t
    [ 8] NONCE                  <Q (random.getrandbits(64))         uint64_t
    [..] USER_AGENT             variable string
    [ 4] HEIGHT                 <i                                  int32_t
    [ 1] RELAY                  <? (since version >= 70001)         bool

    [---ADDR_PAYLOAD---]
    [..] COUNT                  variable integer
    [..] ADDR_LIST              multiple of COUNT (max 1000)
        [ 4] TIMESTAMP          <I                                  uint32_t
        [ 8] SERVICES           <Q                                  uint64_t
        [16] IP_ADDR
            [12] IPV6           (\x00 * 10 + \xFF * 2)              char[12]
            [ 4] IPV4                                               char[4]
        [ 2] PORT               >H                                  uint16_t

    [---PING_PAYLOAD---]
    [ 8] NONCE                  <Q (random.getrandbits(64))         uint64_t

    [---PONG_PAYLOAD---]
    [ 8] NONCE                  <Q (nonce from ping)                uint64_t

    [---INV_PAYLOAD---]
    [..] COUNT                  variable integer
    [..] INVENTORY              multiple of COUNT (max 50000)
        [ 4] TYPE               <I (0=error, 1=tx, 2=block)         uint32_t
        [32] HASH                                                   char[32]

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
        Note: First TX is the Coinbase

    [---GETBLOCKS_PAYLOAD---]
    [ 4] VERSION                <I                                  uint32_t
    [..] COUNT                  variable integer
    [..] BLOCK_HASHES           multiple of COUNT
        [32] BLOCK_HASH                                             char[32]
    [32] LAST_BLOCK_HASH                                            char[32]

    [---GETHEADERS_PAYLOAD---]
    [ 4] VERSION                <I                                  uint32_t
    [..] COUNT                  variable integer
    [..] BLOCK_HASHES           multiple of COUNT
        [32] BLOCK_HASH                                             char[32]
    [32] LAST_BLOCK_HASH                                            char[32]

    [---HEADERS_PAYLOAD---]
    [..] COUNT                  variable integer (max 2000)
    [..] HEADERS                multiple of COUNT
        [ 4] VERSION            <I                                  uint32_t
        [32] PREV_BLOCK_HASH                                        char[32]
        [32] MERKLE_ROOT                                            char[32]
        [ 4] TIMESTAMP          <I                                  uint32_t
        [ 4] BITS               <I                                  uint32_t
        [ 4] NONCE              <I                                  uint32_t
        [..] TX_COUNT           variable integer (always 0)
-------------------------------------------------------------------------------
"""

import sys
import time
import random
import struct #https://docs.python.org/2/library/struct.html#
import hashlib
import socket
import logging
from logging.handlers import RotatingFileHandler
import datetime
from netaddr import *
from cStringIO import StringIO
from binascii import hexlify, unhexlify
import os

from basic_bitcoin_client.connection import *
from basic_bitcoin_client.messages import *
from lib.database import *
from basic_bitcoin_client.blocks import *
from basic_bitcoin_client.transactions import *

LOGFILEDIR = '.'
LOGFILENAME = os.path.join(LOGFILEDIR, 'log-basic-bitcoin-client-crawler.log')

MIN_PROTOCOL_VERSION = 70001
PROTOCOL_VERSION = 70002
SERVICES = 0  # set to 1 for NODE_NETWORK
USER_AGENT = "/pz:0.1/"
HEIGHT = 347706
RELAY = 0  # set to 1 to receive all txs
#DEFAULT_PORT = 8333

#SOCKET_BUFSIZE = 4096
PING_FREQUENCY = 100
HEADER_LEN = 24

MSG_ERROR = 0
MSG_TX = 1
MSG_BLOCK = 2
MSG_FILTERED_BLOCK = 3

all_peer_addr = []


class InventoryMessageError(Exception):
    pass


def configure_logging():
    consolelevel = logging.DEBUG
    filelevel = logging.INFO

    #logging.basicConfig(format='%(name)s:%(asctime)s:%(levelname)s:%(funcName)s:%(module)s:%(message)s', level=logging.DEBUG)
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s:%(levelname)s:%(funcName)s:%(module)s:%(message)s')

    # Console logging
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    ch.setLevel(consolelevel)
    logger.addHandler(ch)

    # File logging (Rotating)
    try:
        rfh = RotatingFileHandler(LOGFILENAME, maxBytes=20000000, backupCount=5)
        rfh.setFormatter(formatter)
        rfh.setLevel(filelevel)
        logger.addHandler(rfh)
    except Exception as e:
        logger.critical('Error accessing log file{}.  Exiting.\n\tException Message: {}'.format(LOGFILENAME, e))
        sys.exit()
    return


def deserialize_int(data):
    # From Bitnodes
    length = struct.unpack("<B", data.read(1))
    if length[0] == 0xFD:
        length = struct.unpack("<H", data.read(2))
    elif length[0] == 0xFE:
        length = struct.unpack("<I", data.read(4))
    elif length[0] == 0xFF:
        length = struct.unpack("<Q", data.read(8))
    return length


def decodeVersion(payload):

    msg = {}
    decodeData = StringIO(payload)

    msg['version'] = struct.unpack("<i", decodeData.read(4))
    msg['services'] = struct.unpack("<Q", decodeData.read(8))
    msg['timestamp'] = struct.unpack("<Q", decodeData.read(8))

    msg['addr_recv_services'] = struct.unpack("<Q", decodeData.read(8))
    msg['addr_recv_ipv6'] = decodeData.read(12)
    msg['addr_recv_ipv4'] = decodeData.read(4)
    msg['addr_recv_port'] = struct.unpack(">H", decodeData.read(2))

    msg['addr_from_services'] = struct.unpack("<Q", decodeData.read(8))
    msg['addr_from_ipv6'] = decodeData.read(12)
    msg['addr_from_ipv4'] = decodeData.read(4)
    msg['addr_from_port'] = struct.unpack(">H", decodeData.read(2))

    msg['nonce'] = struct.unpack("<Q", decodeData.read(8))

    # Need to add user agent, height, and relay

    logger.info('Version Payload')
    logger.debug('----------------')
    logger.debug('Version: %s', msg['version'][0])
    logger.debug('Services: %s', msg['services'][0])
    logger.debug('Timestamp: %s', datetime.datetime.fromtimestamp(msg['timestamp'][0]).strftime('%Y-%m-%d %H:%M:%S'))

    logger.debug('Addr Services (Recv): %s', msg['addr_recv_services'][0])
    logger.debug('Addr IPv6 (Recv): %s', hexlify(msg['addr_recv_ipv6']))
    #print("Addr IPv4 (Recv): " + str(socket.inet_ntoa(msg['addr_recv_ipv4'])))
    logger.debug('Addr IPv4 (Recv): %s', socket.inet_ntoa(msg['addr_recv_ipv4']))
    logger.debug('Addr Port (Recv): %s', msg['addr_recv_port'][0])

    logger.debug('Addr Services (From): %s', msg['addr_from_services'][0])
    logger.debug('Addr IPv6 (From): %s', hexlify(msg['addr_from_ipv6']))
    #print("Addr IPv4 (From): " + str(socket.inet_ntoa(msg['addr_from_ipv4'])))
    logger.debug('Addr IPv4 (From): %s', socket.inet_ntoa(msg['addr_from_ipv4']))
    logger.debug('Addr Port (Recv): %s', msg['addr_recv_port'][0])

    logger.debug('Nonce : %s', msg['nonce'][0])

    return msg


def decodeInvMessage(payload, sock, mesg):

    msg = {}
    inventory = []
    decodeData = StringIO(payload)

    msg['count'] = deserialize_int(decodeData)
    # Make sure inventory message length matches count properly

    msg['inventory'] = decodeData.read((36 * msg['count'][0]))

    logger.debug('Inventory Message(s) - ' + 'Count: %s', msg['count'][0])

    decodeInventoryMsg = StringIO(msg['inventory'])

    #getdatamsg = mesg.getData(msg['count'][0], msg['inventory'])
    #sock.sendall(getdatamsg)

    for x in range(0, msg['count'][0]):

        invTypeCode = decodeInventoryMsg.read(4)
        invType = getInventoryType(struct.unpack("<I", invTypeCode)[0])
        invHash = decodeInventoryMsg.read(32)[::-1]

        inventory.append({'type': invType, 'hash': invHash})
        if invType == 'Msg_Block':
            logger.info('   Inventory Payload - Block Found ' + 'Type: %s' + '      Hash: %s', inventory[x]['type'], hexlify(inventory[x]['hash']))
            writeinv('blockhash.txt', invType, invHash)
            getdatamsg = mesg.getData(1, str(invTypeCode) + str(invHash[::-1]))
            #Send block message request
            sock.sendall(getdatamsg)

        logger.debug('   Inventory Payload - ' + 'Type: %s' + '      Hash: %s', inventory[x]['type'], hexlify(inventory[x]['hash']))

        #writeinv('txhash.txt', invType, invHash)

        if invType == 'Msg_Block':
            #db.insert('blocks', 'hashMerkle', '\'{}\''.format(hexlify(invHash)))
            pass
        elif invType == 'Msg_Tx':
            #db.insert('transactions', 'txHash', '\'{}\''.format(hexlify(invHash)))
            pass

    return msg


def writeinv(filename, invType, invHash):
    with open(filename, 'a') as f:
        f.write(invType + ':' + hexlify(invHash) + '\t' + time.asctime() + '\n')

    return


def getInventoryType(inventorytype):
    typedesc= "Undefined"

    if inventorytype == 0:
        typedesc = "Error"
    elif inventorytype == 1:
        typedesc = "Msg_Tx"
    elif inventorytype == 2:
        typedesc = "Msg_Block"
    elif inventorytype == 3:
        typedesc = "Msg_Filtered_Block"

    return typedesc


def decodeAddrMessage(payload, serverip):

    msg = {}
    addr = []
    decodeData = StringIO(payload)
    db = MyDB('blockchain')

    msg['count'] = deserialize_int(decodeData)
    # Make sure inventory message length matches count properly

    msg['addr'] = decodeData.read((30 * msg['count'][0]))

    logger.info('Address Message(s) - ' + 'Count: %d', msg['count'][0])

    decodeAddrMessage = StringIO(msg['addr'])

    logger.debug('Inserting addresses in DB')
    for x in range(0, msg['count'][0]):

        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(struct.unpack("<I", decodeAddrMessage.read(4))[0]))
        services = decodeAddrMessage.read(8)

        ip = socket.inet_ntoa(decodeAddrMessage.read(16)[-4::]) #[::-1]
        port = struct.unpack(">H", decodeAddrMessage.read(2))[0] #[::-1]

        if ip not in all_peer_addr:
            all_peer_addr.append(ip)
            #logger.debug('Address Payload (%04d' % x + ')\tAddr: %s', ip + '\t\tPort: ' + str(port))

            db.insert('peers',
                      'hostIPAddr, '
                      'peerIPAddr, '
                      'peerPort ', '\'{}\',\'{}\',\'{}\''.format(serverip, ip, str(port)))

        addr.append({'timestamp': timestamp, 'services': services, 'addr': ip, 'port': port})

    #print(addr)
    return msg, addr

def check_peer_connections(addr):
    db = MyDB('blockchain')

    for a in addr[1]:
        tempConn = Connection()
        status = tempConn.openbyip(a['addr'])
        if status == True:
            # Online (probably) - update db
            logger.info("Online:\t{}".format(a['addr']))
            updatestatement = "UPDATE Peers SET peerLastOnline = '{}' WHERE peerIPAddr = '{}'".format(datetime.datetime.now(), a['addr'])
            db.update(updatestatement)
            pass
        else:
            logger.debug("Offline:\t{}".format(a['addr']))

        pass

    pass

def main():
    configure_logging()
    logger.info('\n'*2 + '-'*30 + ' Client starting ' + '-'*30)

    myconn = Connection()
    recv_count = 0
    total_recv_count = 0

    while True:

        logger.info('Attempting to find peer')

        try:
            # Open Connection
            sock = myconn.open()
            mesg = Messages()

            # Send data
            message = mesg.getVersionMsg(myconn.serverIP)
            print >>sys.stderr, 'Sending "%s"' % message
            sock.sendall(message)

            # Look for the response
            amount_received = 0
            amount_expected = SOCKET_BUFSIZE #len(message)

            incompletedata = ''

            while True:
                if len(incompletedata) == 0:
                    data = sock.recv(SOCKET_BUFSIZE)
                else:
                    data = sock.recv(SOCKET_BUFSIZE)# + incompletedata

                amount_received += len(data)
                logger.info('\n')
                logger.info('Time = ' + time.strftime("%I:%M:%S") + '\tMessage received - %s', total_recv_count)

                try:
                    msgs, incompletedata = mesg.checkMsg(incompletedata + data)
                    if len(incompletedata) > 0:
                        logger.debug('Incomplete data length: %d - %s', len(incompletedata), hexlify(incompletedata))
                        if MAGIC_NUMBER not in incompletedata:
                            logger.debug(' MAGIC NUMBER NOT FOUND IN INCOMPLETE DATA!')

                except HeaderTooShortError:
                    logger.warning('Header too short!: %s', sys.exc_info())


                except PayloadTooShortError:
                    logger.warning('Payload too short!: %s', sys.exc_info())
                    continue

                except PayloadChecksumError:
                    logger.warning('Payload checksum error!: %s', sys.exc_info())
                    break

                except:
                    logger.warning('Unexpected error: %s', sys.exc_info())
                    continue

                #mesg.printMsgs(msgs)

                for index in range(0, len(msgs)):
                    msg = msgs[index]

                    if msg['command'] == "version":
                        decodeVersion(msg['payload'])
                        message = mesg.getVerackMsg()
                        logger.debug('Version received, sending \'verack\'')
                        sock.sendall(message)

                    elif msg['command'] == "verack":
                        logger.debug('Verack received, sending \'getAddr\'')
                        sock.sendall(mesg.getAddrMsg())

                        #getblockmsg = mesg.getBlocks(4, 1, '000000000000000000083be09ac9bcdd3313f0324b7105473255c95c8a33d514', 0)
                        #sock.sendall(getblockmsg)
                    elif msg['command'] == "addr":
                        logger.debug('addr received - Addresses: ')
                        # Close connection once addresses are received to avoid receiving further messages
                        sock.close()

                        # Update database and check if addresses are online
                        addr = decodeAddrMessage(msg['payload'], myconn.serverIP)
                        check_peer_connections(addr)
                        break

                    # elif msg['command'] == "getaddr":
                    #     logger.debug('getaddr received')
                    #
                    # elif msg['command'] == "getdata":
                    #     logger.debug(msg['command'] + ' received')
                    # elif msg['command'] == "getheaders":
                    #     logger.debug('getheaders received')
                    elif msg['command'] == "inv":
                         #logger.debug(msg['command'] + ' received')
                         decodeInvMessage(msg['payload'], sock, mesg)
                    elif msg['command'] == "ping":
                         logger.info('Ping received, sending \'pong\'')
                         sock.sendall(mesg.getPongMsg(msg['payload']))
                    # elif msg['command'] == "block":
                    #     logger.info('\n' + '-'*30 + ' Block Mined ' + '-'*30 + '\n')
                    #     logger.debug('Block: {}'.format(msg))
                    #     blockinfo, txdata = block.parseblock(msg)
                    #     tx.parsetx(txdata, blockinfo['txcount'])
                    else:
                        logger.debug('----------------- ' + msg['command'] + ' received')

                recv_count = recv_count + 1
                total_recv_count = total_recv_count + 1

                # Send 'ping' periodically
                if recv_count > PING_FREQUENCY:
                    message = mesg.getPingMsg()
                    print >>sys.stderr, '\nsending "%s"' % message
                    sock.sendall(message)
                    recv_count = 0

            #print >>sys.stderr, 'received "%s"' % data

        except:
            logger.warning('Unexpected error: %s', sys.exc_info())

        finally:
            if myconn.sock is not None:
                myconn.sock.close()
                print >>sys.stderr, 'closing socket after "%d" recvs' %total_recv_count
            logger.info('-'*30 + ' Client stopping ' + '-'*30)


if __name__ == '__main__':
    main()