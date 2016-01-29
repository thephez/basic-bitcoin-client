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

logger = logging.getLogger()

class HeaderTooShortError(Exception):
    pass


class PayloadTooShortError(Exception):
    pass


class PayloadChecksumError(Exception):
    pass


class Messages():

    def checkMsg(self, data):
        recvmsg = {}
        all_msgs = []
        #logger.debug(hexlify(data))

        data_len = len(data)
        if data_len < HEADER_LEN:
            raise HeaderTooShortError("got {} of {} bytes".format(
                data_len, HEADER_LEN))

        dataIO = StringIO(data)

        logger.info('Received data length: %d', len(data))

        # Check for multiple messages
        while dataIO.tell() < len(data):

            remainingdatalength = len(data) - dataIO.tell()

            if len(data) - dataIO.tell() < HEADER_LEN:
                raise HeaderTooShortError("Received {} of {} bytes".format(
                    data_len, HEADER_LEN))

            if data[0:4] == MAGIC_NUMBER:
                recvmsg['magic_number'] = dataIO.read(4)
                #logger.debug('Magic Number received - %s', hexlify(recvmsg['magic_number']))

                recvmsg['command'] = dataIO.read(12).strip("\x00") # Remove Nulls at end of string
                logger.info('  Command: %s', recvmsg['command'])

                recvmsg['length'] = struct.unpack("<I", dataIO.read(4))[0]

                if recvmsg['length'] > (remainingdatalength - HEADER_LEN):
                    logger.info('Incomplete Payload - need to wait for more data: %d remaining', (recvmsg['length'] + HEADER_LEN)- remainingdatalength)
                    logger.info('data_len: %d, dataIO.tell(): %d, recvmsg[length]: %d' % (data_len, dataIO.tell(), recvmsg['length']))
                    # The data[x:x] items need to be modified in case the short message is in the middle of a list of messages (may not start at [0:4]
                    return(all_msgs, data[0:4] + data[4:16] + data[16:20] + dataIO.read(data_len - dataIO.tell()))

                    #raise PayloadTooShortError("Received {} of {} bytes".format(
                    #    remainingdatalength - HEADER_LEN, recvmsg['length']))
                else:
                    recvmsg['checksum'] = dataIO.read(4)
                    logger.debug('  Checksum: %s', str(hexlify(recvmsg['checksum'])))

                    recvmsg['payload'] = dataIO.read(recvmsg['length'])
                    logger.debug('  Payload: %s\n', hexlify(recvmsg['payload']))

                    checksum = hashlib.sha256(hashlib.sha256(recvmsg['payload']).digest()).digest()[0:4]

                    if checksum != recvmsg['checksum']:
                        raise PayloadChecksumError("got {} instead of {} ".format(
                            hexlify(checksum), hexlify(recvmsg['checksum'])))

                #https://docs.python.org/2/library/stdtypes.html
                all_msgs.append(recvmsg.copy())
            else:
                # Temp. bypass for data that doesn't fit in single message (most commonly addr)
                # Need to rewrite to handle these messages
                recvmsg['command'] = 'Data w/out Magic number'
                all_msgs.append(recvmsg.copy())
                logger.debug('Length of leftover data: %d', dataIO.tell())
                logger.debug(all_msgs)
                return (all_msgs, dataIO.read())

        return (all_msgs, '')

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
        payload = ""

        return self.makeMessage(MAGIC_NUMBER, 'verack', payload)

    def getPingMsg(self):
        nonce = random.getrandbits(64)
        payload = struct.pack('<Q', nonce)
        logger.debug('getPingMsg nonce = %s', hexlify(payload))
        # Q - unsigned long long (integer 8)

        return self.makeMessage(MAGIC_NUMBER, 'ping', payload)

    def getPongMsg(self, payload):
        #print(hexlify(payload))
        logger.debug('getPongMsg nonce = %s\n', hexlify(payload))

        return self.makeMessage(MAGIC_NUMBER, 'pong', payload)

    def getAddrMsg(self):
        logger.debug('------------------------------------------------------getAddrMsg---------------------------------')
        payload = ''

        return self.makeMessage(MAGIC_NUMBER, 'getaddr', payload)

    def getData(self, count, invMsg):
        logger.debug('count = {}.\tinvMsg {}'.format(count, hexlify(invMsg)))
        count = self.serialize_int(count)

        payload = str(count) + str(invMsg) #str(invMsg[0:4]) + str(invMsg[4:])
        msg = self.makeMessage(MAGIC_NUMBER, 'getdata', payload)
        logger.debug('GetData message: {}\n{}'.format(msg, hexlify(msg)))

        return msg

    def getBlocks(self, version, hashcount, locatehash, stophash):
        logger.info('getBlocks')

        version = struct.pack("<I", version)
        hashcount = chr(1)
        locatehash = unhexlify(locatehash)
        if stophash == 0:
            stophash = '0000000000000000000000000000000000000000000000000000000000000000'

        stophash = unhexlify(stophash)

        print('Version: {}\tCount: {}\t Start Hash: {}\tStop Hash: {}'.format(version, hashcount, locatehash, stophash))
        payload = str(version) + str(hashcount) + locatehash + str(stophash)
        print(hexlify(payload))
        print('{}'.format(payload))
        msg = self.makeMessage(MAGIC_NUMBER, 'getblocks', payload)
        print('{}\n{}'.format(msg, hexlify(msg)))
        return msg

    def printMsgs(self, message):
        print('printMsgs - ' + 'length of msgs = ' + str(len(message)))
        for index in range(0, len(message)):
            print('printMsgs - ' + str(index) + ' ' + str(message[index]))

    def serialize_int(self, value):

        if value < 0xFD:
            return struct.pack("<B", value)
        elif value <= 0xFFFF:
            return chr(0xFD) + struct.pack("<H", value) # 0xFD + length as uint_16
        elif value < 0xFFFFFFFF:
            return chr(0xFE) + struct.pack("<I", value) # 0xFE + length as uint_32
        else:
            return chr(0xFF) + struct.pack("<Q", value) # 0xFF + length as uint_64
