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
import struct
import hashlib
import socket
from netaddr import *
from cStringIO import StringIO
from binascii import hexlify, unhexlify

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
# L - unsigned long (integer 4)
# Q - unsigned long long (integer 8)
# Q - unsigned long long (integer 8)
# s - char[26]
# s - char[26]
# Q - unsigned long long (integer 8)
# s - char[]
# L - unsigned long (integer 4)

    return makeMessage(magic, 'version', payload)

def getPeerIP():
    peerInfo = socket.getaddrinfo('bitseed.xf2.org', 80)
    #print(peerInfo)
    return peerInfo


def checkMsg(data):
    msg = {}
    #print data[0:4]
    #print MAGIC_NUMBER
    dataIO = StringIO(data)

    print("Received data length: " + str(len(data)))
    
    if data[0:4] == MAGIC_NUMBER:
        msg['magic_number'] = dataIO.read(4)
        print("Magic Number received - " + str(hexlify(msg['magic_number'])))

        msg['command'] = dataIO.read(12).strip("\x00") # Remove Nulls at end of string
        print("Command: " + msg['command']) #+ str(dataIO.read(12)))
        
        msg['length'] = struct.unpack("<I", dataIO.read(4))[0]
        print("Payload Length: " + str(msg['length'])) #str(struct.unpack("<I", dataIO.read(4))[0]))

        msg['checksum'] = dataIO.read(4)
        print("Checksum : " + str(hexlify(msg['checksum'])) + " --- ") #+ str(struct.unpack("<I", checksum)[0]))

        msg['payload'] = dataIO.read(msg['length'])
        print("Payload: " + str(hexlify(msg['payload'])))

        #print("Command: " + data[4:16])
        #print(dataIO.read(4))
        #print(struct.unpack("<I", data.read(4))[0])
        #checksum = dataIO.read(4)
        #print(len(data))
        
    print("recv " + ":".join(x.encode('hex') for x in data))


peerInfo = getPeerIP()
print peerInfo[0][4][0]

serverIP = peerInfo[0][4][0] # IP Address of reply 2
serverIP = '71.232.77.250'
serverIP = '24.146.187.40'

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect the socket to the port where the server is listening
server_address = (serverIP, DEFAULT_PORT) #('50.177.196.160', DEFAULT_PORT)
print >>sys.stderr, 'connecting to %s port %s' % server_address

try:
    sock.connect(server_address)

    
    # Send data
    #message = 'This is the message.  It will be repeated.'
    #message = MAGIC_NUMBER + 'version' + 0 + checksum
    message = getVersionMsg(serverIP)
    print >>sys.stderr, 'sending "%s"' % message
    sock.sendall(message)

    # Look for the response
    amount_received = 0
    amount_expected = SOCKET_BUFSIZE #len(message)

    data = sock.recv(SOCKET_BUFSIZE)
    checkMsg(data)
    while amount_received < amount_expected:
#    while len(data) > 0:
        data = sock.recv(SOCKET_BUFSIZE)
        amount_received += len(data)
        checkMsg(data)
        print >>sys.stderr, 'received "%s"' % data

    #print >>sys.stderr, 'received "%s"' % data
        

finally:
    print >>sys.stderr, 'closing socket'
    sock.close()
