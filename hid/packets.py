"""Contains classes to process and manage HID packets

Classes:

 * :class:`HIDPacket`
 * :class:`HIDInitializationPacket`
 * :class:`HIDContinuationPacket`

"""
"""
 © Copyright 2020-2021 University of Surrey

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
 this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright notice,
 this list of conditions and the following disclaimer in the documentation
 and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.

"""
from abc import ABC, abstractmethod
import json
import ctap.constants

class HIDPacket(ABC):
    """HIDPacket is the super class for initialization packets
    and continuation packets. Contains basic functionality
    shared by both.

    """
    _BROADCAST_ID = b'\xff\xff\xff\xff'

    def __init__(self, data):
        self._data = data

    def get_bytes(self)->bytes:
        """Gets the bytes associated with this packet. This
        automatically trims the returned bytes to the correct
        length, removing any padding.

        Returns:
            bytes: content of packet without padding
        """
        if len(self._data) < 64:
            return self._data + bytes(64-len(self._data))
        return self._data

    @abstractmethod
    def get_payload(self)->bytes:
        """Gets the complete payload including padding

        Returns:
            bytes: complete payload
        """

    @classmethod
    def from_bytes(cls, packet:bytes)->'HIDPacket':
        """Statis method to instantiate a packet from its
        byte representation.

        Args:
            packet (bytes): packet as bytes

        Returns:
            [HIDPacket]: an instance of either HIDInitializationPacket
                or HIDContinuationPacket depending on size
        """
        if packet[4] & (1 << 7):
            return HIDInitializationPacket.from_bytes(packet)
        return HIDContinuationPacket.from_bytes(packet)

    @abstractmethod
    def debug_str(self):
        """Encodes the underlying packet as a string to allow it to
        be easily logged
        """


class HIDInitializationPacket(HIDPacket):
    """HID Initialization Packet consisting of:

        Offset 	Length 	Mnemonic 	Description
            0 	4 	    CID 	Channel identifier
            4 	1 	    CMD 	Command identifier (bit 7 always set)
            5 	1 	    BCNTH 	High part of payload length
            6 	1 	    BCNTL 	Low part of payload length
            7 	(s - 7) DATA 	Payload data (s is equal to the fixed packet size)


    """
    CMDTYPE = ctap.constants.CMD_TYPE.INITIALIZATION

    def __init__(self, cid:bytes, cmd:ctap.constants.CTAP_CMD, length:int, payload:bytes):
        self._cid=cid
        self._cmd=cmd
        self._length=length
        self._payload=payload
        packet = bytearray(64)
        packet[0:4] = self._cid

        packet[4] = self._cmd.value[0] ^ (1 << 7)
        packet[5:7]=self._length.to_bytes(2,'big')
        packet[7:] = self._payload
        if self._length > (64 - 7):
            self._has_sequence = True
        else:
            self._has_sequence = False
        super().__init__(packet)

    def __str__(self):
        out = {}
        out["CID"]=self._cid.hex()
        out["CMD"]=self._cmd.name
        out["length"] = self._length
        out["payload"] = self._payload.hex()
        return json.dumps(out)

    def get_cmd(self)->bytes:
        """Gets CMD bytes

        Returns:
            bytes: CMD bytes
        """
        return self._cmd

    def get_length(self)->int:
        """Gets length of the packet

        Returns:
            int: length of packet
        """
        return self._length

    def get_payload(self)->bytes:
        """Gets the payload bytes

        Returns:
            bytes: payload
        """
        return self._payload

    def get_cid(self)->bytes:
        """Gets the channel ID

        Returns:
            bytes: channel ID bytes
        """
        return self._cid

    @classmethod
    def from_bytes(cls, packet:bytes):
        channel_id = packet[:4]
        cmd = ctap.constants.CTAP_CMD((packet[4] & ~(1 << 7)).to_bytes(1,"big"))
        message_length = int.from_bytes(packet[5:7], "big")
        data = packet[7:]
        return HIDInitializationPacket(channel_id, cmd, message_length, data)

    def debug_str(self):
        return self.__str__()


class HIDContinuationPacket(HIDPacket):
    """HID Continuation Packet consists of:

    Offset 	Length 	Mnemonic 	Description
        0 	4 	    CID 	Channel identifier
        4 	1 	    SEQ 	Packet sequence 0x00..0x7f (bit 7 always cleared)
        5 	(s - 5) DATA 	Payload data (s is equal to the fixed packet size)

    """
    CMDTYPE = ctap.constants.CMD_TYPE.CONTINUATION

    def __init__(self, cid:bytes, seq:int, payload:bytes):
        self._cid=cid
        self._seq=seq
        self._payload=payload
        packet = bytearray(64)
        packet[0:4] = self._cid
        packet[4] = self._seq & ~(1 << 7)
        packet[5:] = self._payload
        super().__init__(packet)

    def __str__(self):
        out = {}
        out["CID"]=self._cid.hex()
        out["SEQ"]=self._seq
        out["payload"] = self._payload.hex()
        return json.dumps(out)

    def get_payload(self)->bytes:
        return self._payload
    def get_sequence(self)->int:
        """Gets the sequence number for this packet

        Returns:
            int: sequence number
        """
        return self._seq
    @classmethod
    def from_bytes(cls, packet:bytes):
        channel_id = packet[:4]
        seq = packet[4]
        data = packet[5:]
        return HIDContinuationPacket(channel_id, seq, data)


    def debug_str(self):
        return self.__str__()
