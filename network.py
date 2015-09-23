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

import socket
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

#logging.basicConfig()
logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


magic = 0xd9b4bef9
MAGIC_NUMBER = "\xF9\xBE\xB4\xD9"
MIN_PROTOCOL_VERSION = 70001
PROTOCOL_VERSION = 70002
SERVICES = 0  # set to 1 for NODE_NETWORK
USER_AGENT = "/pz:0.1/"
HEIGHT = 347706
RELAY = 0  # set to 1 to receive all txs
DEFAULT_PORT = 8333

SOCKET_BUFSIZE = 4096
PING_FREQUENCY = 10


class PeerNotFound(Exception):
    pass


def makeMessage(magic, command, payload):
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[0:4]
    return struct.pack('L12sL4s', magic, command, len(payload), checksum) + payload
    # L - unsigned long
    # s - char[12]
    # L - unsigned long
    # s - char[4]
 
def getVersionMsg(serverIP):
    version = 60002
    services = 1
    timestamp = int(time.time())
    addr_me = '127.0.0.1' #serverIP #utils.netaddr(socket.inet_aton("127.0.0.1"), 8333)
    addr_you = serverIP #"50.177.196.160" #utils.netaddr(socket.inet_aton("71.232.77.250"), 8333)
    nonce = random.getrandbits(64)
    sub_version_num = "" #utils.varstr('')
    start_height = 0
 
    payload = struct.pack('<LQQ26s26sQsL', version, services, timestamp, addr_me,
        addr_you, nonce, sub_version_num, start_height)
    # < - little-endian
    # > - big-endian
    # L - unsigned long (integer 4)
    # Q - unsigned long long (integer 8)
    # Q - unsigned long long (integer 8)
    # s - char[26]
    # s - char[26]
    # Q - unsigned long long (integer 8)
    # s - char[]
    # L - unsigned long (integer 4)

    return makeMessage(magic, 'version', payload)

def getVerackMsg():
    payload = "" #struct.pack('<LQQ26s26sQsL', "verack")
    # L - unsigned long (integer 4)
    # Q - unsigned long long (integer 8)
    # Q - unsigned long long (integer 8)
    # s - char[26]
    # s - char[26]
    # Q - unsigned long long (integer 8)
    # s - char[]
    # L - unsigned long (integer 4)

    return makeMessage(magic, 'verack', payload)

def getPingMsg():
    nonce = random.getrandbits(64)
    payload = struct.pack('<Q', nonce)
    logger.debug('getPingMsg nonce = %s', hexlify(payload))
    # Q - unsigned long long (integer 8)

    return makeMessage(magic, 'ping', payload)

def getPeerIP():
    socket_timeout = 3
    peerInfo = socket.getaddrinfo('seed.bitcoinstats.com', 80)
    #peerInfo = socket.getaddrinfo('bitseed.xf2.org', 80)

    # Randomly order list so the same node isn't picked every time
    random.shuffle(peerInfo)

    logger.debug('%d clients found', len(peerInfo))

    # Loop through all returned IP addresses until valid connection made
    for index in range(len(peerInfo)):

        # Create a TCP/IP socket and set timeout to 4 seconds
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(socket_timeout)

        # Get IP address to test
        serverIP = peerInfo[index][4][0]

        # Connect the socket to the port where the server is listening
        server_address = (serverIP, DEFAULT_PORT) # ('50.177.196.160', DEFAULT_PORT)

        try:
            #print >>sys.stderr, '\nConnecting to %s port %s' % server_address
            sock.connect(server_address)
            #print("Connection successful")
            return peerInfo[index][4][0]

        except:
            logger.warning('Unexpected error: Server IP: %s %s', serverIP, sys.exc_info())
            pass

        finally:
            print >>sys.stderr, 'Closing socket'
            sock.close()

    raise(PeerNotFound)
    return -1


def checkMsg(data):
    msg = {}
    #print data[0:4]
    #print MAGIC_NUMBER
    dataIO = StringIO(data)

    logger.debug('Received data length: %d', len(data))

    if data[0:4] == MAGIC_NUMBER:
        msg['magic_number'] = dataIO.read(4)
        logger.debug('Magic Number received - %s', hexlify(msg['magic_number']))

        msg['command'] = dataIO.read(12).strip("\x00") # Remove Nulls at end of string
        logger.debug('  Command: %s', msg['command'])
        
        msg['length'] = struct.unpack("<I", dataIO.read(4))[0]
        logger.debug('  Payload Length: %d', msg['length'])

        msg['checksum'] = dataIO.read(4)
        logger.debug('  Checksum: %s', msg['checksum'])

        msg['payload'] = dataIO.read(msg['length'])
        logger.debug('  Payload: %s\n', msg['payload'])

        #print("Command: " + data[4:16])
        #print(dataIO.read(4))
        #print(struct.unpack("<I", data.read(4))[0])
        #checksum = dataIO.read(4)
        #print(len(data))
        
    #print("recv " + ":".join(x.encode('hex') for x in data))

    return msg


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
    decodeData = StringIO(payload)

    msg['count'] = deserialize_int(decodeData)
    msg['inventory'] = decodeData.read((36 * msg['count'][0]))
    
    logger.info('Inventory Message(s) - ' + 'Count: %s', msg['count'][0])
    #logger.debug('----------------')
    #logger.debug('Count: %s', msg['count'][0])
    #logger.debug('Inventory: %s', msg['inventory'])

    for x in range(0, msg['count'][0]):
        decodeInventory(msg['inventory'])

    return msg


def decodeInventory(payload):

    msg = {}
    decodeData = StringIO(payload)

    msg['type'] = struct.unpack("<I", decodeData.read(4))[0]
    msg['hash'] = decodeData.read(32)

    logger.info('   Inventory Payload - ' + 'Type: %s', getInventoryType(msg['type']))
    #logger.debug('  ----------------')
    #logger.debug('  Type: %s', getInventoryType(msg['type']))
    #logger.debug('  Hash: %s', msg['hash'])

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


recv_count = 0
total_recv_count = 0
serverIP = getPeerIP()
logger.info('Server IP: %s', serverIP)

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect the socket to the port where the server is listening
server_address = (serverIP, DEFAULT_PORT) #('50.177.196.160', DEFAULT_PORT)
print >>sys.stderr, '\nconnecting to %s port %s' % server_address

try:
    sock.connect(server_address)
    
    # Send data
    message = getVersionMsg(serverIP)
    print >>sys.stderr, 'sending "%s"' % message
    sock.sendall(message)

    # Look for the response
    amount_received = 0
    amount_expected = SOCKET_BUFSIZE #len(message)

    data = sock.recv(SOCKET_BUFSIZE)

    # Check received message and issue 'verack' if 'version' received
    msg = checkMsg(data)

    if msg['command'] == "version":
        decodeVersion(msg['payload'])
        message = getVerackMsg()
        logger.debug('Version received, sending \'verack\'')
        sock.sendall(message)
    elif msg['command'] == "inv":
        decodeInvMessage()
    elif msg['command'] == "ping":
        logging.debug("Ping Received")

    while amount_received < amount_expected:
#    while len(data) > 0:
        data = sock.recv(SOCKET_BUFSIZE)
        amount_received += len(data)
        msg = checkMsg(data)
        #print >>sys.stderr, '\nreceived "%s"' % data
        logger.info('Message received - %s', total_recv_count)

        if msg['command'] == "version":
            decodeVersion(msg['payload'])
            message = getVerackMsg()
            logger.debug('Version received, sending \'verack\'')
            sock.sendall(message)
        elif msg['command'] == "inv":
            decodeInvMessage(msg['payload'])
        elif msg['command'] == "ping":
            logger.debug('Ping received, need to send \'pong\'')

        
        recv_count = recv_count + 1
        total_recv_count = total_recv_count + 1

        # Send 'ping' periodically        
        if recv_count > PING_FREQUENCY:
            message = getPingMsg()
            print >>sys.stderr, '\nsending "%s"' % message
            sock.sendall(message)
            recv_count = 0
           
    #print >>sys.stderr, 'received "%s"' % data
        

finally:
    print >>sys.stderr, 'closing socket after "%d" recvs' %total_recv_count
    sock.close()
