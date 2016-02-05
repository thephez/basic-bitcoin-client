import struct


class Util():
    def __init__(self):
        pass

    def deserialize_int(self, data):
        # From Bitnodes
        length = struct.unpack("<B", data.read(1))
        if length[0] == 0xFD:
            length = struct.unpack("<H", data.read(2))
        elif length[0] == 0xFE:
            length = struct.unpack("<I", data.read(4))
        elif length[0] == 0xFF:
            length = struct.unpack("<Q", data.read(8))
        return length

    def serialize_int(self, value):

        if value < 0xFD:
            return struct.pack("<B", value)
        elif value <= 0xFFFF:
            return chr(0xFD) + struct.pack("<H", value) # 0xFD + length as uint_16
        elif value < 0xFFFFFFFF:
            return chr(0xFE) + struct.pack("<I", value) # 0xFE + length as uint_32
        else:
            return chr(0xFF) + struct.pack("<Q", value) # 0xFF + length as uint_64