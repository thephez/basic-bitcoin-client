import sys
import time
import random
import struct #https://docs.python.org/2/library/struct.html#
import hashlib
import logging
import datetime
from cStringIO import StringIO
from binascii import hexlify, unhexlify

MAGIC_NUMBER = "\xF9\xBE\xB4\xD9"
HEADER_LEN = 24

logger = logging.getLogger("logger")


class HeaderTooShortError(Exception):
    pass


class Messages():

    def checkMsg(self, data):
        recvmsg = {}
        all_msgs = []
        logger.debug(hexlify(data))
        #print data[0:4]

        data_len = len(data)
        if data_len < HEADER_LEN:
            raise HeaderTooShortError("got {} of {} bytes".format(
                data_len, HEADER_LEN))

        dataIO = StringIO(data)

        logger.debug('Received data length: %d', len(data))

        # Check for multiple messages
        while dataIO.tell() < len(data):

            if len(data) - dataIO.tell() < HEADER_LEN:
                raise HeaderTooShortError("got {} of {} bytes".format(
                    data_len, HEADER_LEN))

            if data[0:4] == MAGIC_NUMBER:
                recvmsg['magic_number'] = dataIO.read(4)
                #logger.debug('Magic Number received - %s', hexlify(recvmsg['magic_number']))

                recvmsg['command'] = dataIO.read(12).strip("\x00") # Remove Nulls at end of string
                logger.info('  Command: %s', recvmsg['command'])

                recvmsg['length'] = struct.unpack("<I", dataIO.read(4))[0]
                logger.debug('  Payload Length: %d', recvmsg['length'])

                recvmsg['checksum'] = dataIO.read(4)
                logger.info('  Checksum: %s', str(hexlify(recvmsg['checksum'])))

                recvmsg['payload'] = dataIO.read(recvmsg['length'])
                logger.debug('  Payload: %s\n', hexlify(recvmsg['payload']))

                #https://docs.python.org/2/library/stdtypes.html
                all_msgs.append(recvmsg.copy())

                #printMsgs(all_msgs)

        #print("recv " + ":".join(x.encode('hex') for x in data))
        #print("String IO Length = " + str(dataIO.tell()))

        return all_msgs

    def makeMessage(self, magic, command, payload):
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[0:4]

        magic = struct.unpack("<I", magic)[0]

        return struct.pack('L12sL4s', magic, command, len(payload), checksum) + payload
        # L - unsigned long
        # s - char[12]
        # L - unsigned long
        # s - char[4]

    def getVersionMsg(self, serverIP):
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

        return self.makeMessage(MAGIC_NUMBER, 'version', payload)

    def getVerackMsg(self):
        payload = "" #struct.pack('<LQQ26s26sQsL', "verack")
        # L - unsigned long (integer 4)
        # Q - unsigned long long (integer 8)
        # Q - unsigned long long (integer 8)
        # s - char[26]
        # s - char[26]
        # Q - unsigned long long (integer 8)
        # s - char[]
        # L - unsigned long (integer 4)

        return self.makeMessage(MAGIC_NUMBER, 'verack', payload)

    def getPingMsg(self):
        nonce = random.getrandbits(64)
        payload = struct.pack('<Q', nonce)
        logger.debug('getPingMsg nonce = %s', hexlify(payload))
        # Q - unsigned long long (integer 8)

        return self.makeMessage(MAGIC_NUMBER, 'ping', payload)

    def getPongMsg(self, payload):
        print(hexlify(payload))
        logger.debug('getPongMsg nonce = %s\n', hexlify(payload))

        return self.makeMessage(MAGIC_NUMBER, 'pong', payload)

    def getAddrMsg(self):
        print('------------------------------------------------------getAddrMsg---------------------------------')
        logger.debug('getAddr')
        payload = ''

        return self.makeMessage(MAGIC_NUMBER, 'getaddr', payload)

    def printMsgs(self, message):
        print('printMsgs - ' + 'length of msgs = ' + str(len(message)))
        for index in range(0, len(message)):
            print('printMsgs - ' + str(index) + ' ' + str(message[index]))