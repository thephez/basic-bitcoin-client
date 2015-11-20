import sys
import random
import socket
import logging
import datetime
from netaddr import *
from cStringIO import StringIO
from binascii import hexlify, unhexlify

DEFAULT_PORT = 8333
SOCKET_BUFSIZE = 4096

logger = logging.getLogger("logger")

class PeerNotFound(Exception):
    pass


class Connection():
    def __init__(self):
        self.serverIP = ''
        self.sock = None

    def get_peer_IP(self):
        socket_timeout = 3
        peerinfo = socket.getaddrinfo('seed.bitcoinstats.com', 80)
        #peerInfo = socket.getaddrinfo('bitseed.xf2.org', 80)

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
        return -1

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
            print >>sys.stderr, 'aslkdfj'

    def close(self):

        self.sock.close()