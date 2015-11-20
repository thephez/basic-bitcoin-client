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
import datetime
from netaddr import *
from cStringIO import StringIO
from binascii import hexlify, unhexlify

from connection import *
from messages import *

logging.basicConfig(format='%(funcName)s:%(levelname)s:%(message)s', level=logging.DEBUG)
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
#logger.setLevel(logging.INFO)

MIN_PROTOCOL_VERSION = 70001
PROTOCOL_VERSION = 70002
SERVICES = 0  # set to 1 for NODE_NETWORK
USER_AGENT = "/pz:0.1/"
HEIGHT = 347706
RELAY = 0  # set to 1 to receive all txs
DEFAULT_PORT = 8333

SOCKET_BUFSIZE = 4096
PING_FREQUENCY = 100
HEADER_LEN = 24

MSG_ERROR = 0
MSG_TX = 1
MSG_BLOCK = 2
MSG_FILTERED_BLOCK = 3


class InventoryMessageError(Exception):
    pass


def deserialize_int(data):
    # From Bitnodes
    length = struct.unpack("<B", data.read(1))
    if length == 0xFD:
        length = struct.unpack("<H", data.read(2))
    elif length == 0xFE:
        length = struct.unpack("<I", data.read(4))
    elif length == 0xFF:
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


def decodeInvMessage(payload):

    msg = {}
    inventory = []
    decodeData = StringIO(payload)

    msg['count'] = deserialize_int(decodeData)
    # Make sure inventory message length matches count properly

    msg['inventory'] = decodeData.read((36 * msg['count'][0]))

    logger.debug('Inventory Message(s) - ' + 'Count: %s', msg['count'][0])

    decodeInventoryMsg = StringIO(msg['inventory'])

    for x in range(0, msg['count'][0]):

        invType = getInventoryType(struct.unpack("<I", decodeInventoryMsg.read(4))[0])
        invHash = decodeInventoryMsg.read(32)[::-1]

        inventory.append({'type': invType, 'hash': invHash})
        if invType == 'Msg_Block':
            logger.info('   Inventory Payload - Block Found ' + 'Type: %s' + '      Hash: %s', inventory[x]['type'], hexlify(inventory[x]['hash']))
        logger.debug('   Inventory Payload - ' + 'Type: %s' + '      Hash: %s', inventory[x]['type'], hexlify(inventory[x]['hash']))

    return msg


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


myconn = Connection()

recv_count = 0
total_recv_count = 0

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

    while 1 == 1:
        data = sock.recv(SOCKET_BUFSIZE)
        amount_received += len(data)

        logger.info('Time = ' + time.strftime("%I:%M:%S"))
        logger.info('Message received - %s', total_recv_count)
        msgs = mesg.checkMsg(data)

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
                #sock.sendall(mesg.getAddrMsg())
            elif msg['command'] == "addr":
                logger.debug('addr received')
            elif msg['command'] == "getaddr":
                logger.debug('getaddr received')
            elif msg['command'] == "getdata":
                logger.debug(msg['command'] + ' received')
            elif msg['command'] == "getheaders":
                logger.debug('getheaders received')
            elif msg['command'] == "inv":
                logger.debug(msg['command'] + ' received')
                decodeInvMessage(msg['payload'])
            elif msg['command'] == "ping":
                logger.info('Ping received, sending \'pong\'')
                sock.sendall(mesg.getPongMsg(msg['payload']))
            elif msg['command'] == "block":
                logger.info('\n\n\n\n\n------------------------------- Block Mined -------------------------------\n\n\n\n\n')
                logger.debug(msg)
            else:
                logger.info('------------------------------------------------------------------------------------------------------------------- ' + msg['command'] + ' received')

        recv_count = recv_count + 1
        total_recv_count = total_recv_count + 1

        # Send 'ping' periodically
        if recv_count > PING_FREQUENCY:
            message = mesg.getPingMsg()
            print >>sys.stderr, '\nsending "%s"' % message
            sock.sendall(message)
            recv_count = 0
           
    #print >>sys.stderr, 'received "%s"' % data
        

finally:
    print >>sys.stderr, 'closing socket after "%d" recvs' %total_recv_count
    myconn.sock.close()
