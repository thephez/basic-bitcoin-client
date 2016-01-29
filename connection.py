import sys
import random
import socket
import logging
import time
import datetime
from netaddr import *
from cStringIO import StringIO
from binascii import hexlify, unhexlify

DEFAULT_PORT = 8333
SOCKET_BUFSIZE = 4096

logger = logging.getLogger()

class PeerNotFound(Exception):
    pass


class Connection():
    def __init__(self):
        self.serverIP = ''
        self.sock = None

    def get_peer_IP(self):
        socket_timeout = 3
        peerinfo = None

        seedlist = ['seed.bitcoinstats.com', 'bitseed.xf2.org', 'seed.bitcoin.sipa.be', 'dnsseed.bluematt.me', 'dnsseed.bitcoin.dashjr.org']

        while True:
            random.shuffle(seedlist)

            for seed in seedlist:
                logger.debug('Looking for peers on: %s', seed)

                try:
                    peerinfo = socket.getaddrinfo(seed, 80)
                    logger.info('Peer(s) found via: %s', seed)
                    return self.getpeeronseed(peerinfo, socket_timeout)
                    break

                except:
                    logger.warning('Unexpected error: %s', sys.exc_info())
                    continue

            logger.info('No peers found.  Retrying...')
            time.sleep(10)

        raise(PeerNotFound)

    def getpeeronseed(self, peerinfo, socket_timeout):

        # Randomly order list so the same node isn't picked every time
        random.shuffle(peerinfo)

        logger.debug('%d clients found', len(peerinfo))

        # Loop through all returned IP addresses until valid connection made
        for index in range(len(peerinfo)):

            # Create a TCP/IP socket and set timeout to 4 seconds
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(socket_timeout)

            # Get IP address to test
            serverIP = peerinfo[index][4][0]

            # Connect the socket to the port where the server is listening
            server_address = (serverIP, DEFAULT_PORT) # ('50.177.196.160', DEFAULT_PORT)

            try:
                #print >>sys.stderr, '\nConnecting to %s port %s' % server_address
                self.sock.connect(server_address)
                #print("Connection successful")
                logger.info('Server IP: %s', serverIP)
                return peerinfo[index][4][0]

            except:
                logger.warning('Unexpected error: Server IP: %s %s', serverIP, sys.exc_info())
                pass

            finally:
                print >>sys.stderr, 'Closing socket'
                self.sock.close()

        raise(PeerNotFound)

    def open(self):

        self.serverIP = self.get_peer_IP()

        # Create a TCP/IP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect the socket to the port where the server is listening
        server_address = (self.serverIP, DEFAULT_PORT) #('50.177.196.160', DEFAULT_PORT)
        print >>sys.stderr, '\nConnecting to %s port %s' % server_address

        try:
            self.sock.connect(server_address)
            return self.sock
        finally:
            print >>sys.stderr, 'Open Connection'

    def close(self):

        try:
            if self.sock is not None:
                self.sock.close()
        except:
            logger.warning('Unexpected error: %s', sys.exc_info())