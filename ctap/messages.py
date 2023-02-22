"""Contains the classes that handle CTAP message requests
and responses. Requests classes include verification of
the submitted parameters

Classes:

 * :class:`CTAPHIDCMD`
 * :class:`CTAPHIDMsgRequest`
 * :class:`CTAPHIDMsgResponse`
 * :class:`CTAPHIDCancelRequest`
 * :class:`CTAPHIDCancelResponse`
 * :class:`CTAPHIDKeepAliveResponse`
 * :class:`CTAPHIDErrorResponse`
 * :class:`CTAPHIDWinkRequest`
 * :class:`CTAPHIDWinkResponse`
 * :class:`CTAPHIDPingRequest`
 * :class:`CTAPHIDPingResponse`
 * :class:`CTAPHIDCBORRequest`
 * :class:`CTAPHIDCBORResponse`
 * :class:`CTAPHIDInitRequest`
 * :class:`CTAPHIDInitResponse`
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
import logging
import json

from hid.packets import HIDInitializationPacket,HIDContinuationPacket,HIDPacket
from bridge.datatypes import AuthenticatorVersion
from ctap.exceptions import CTAPHIDException
import ctap.constants

logging.basicConfig()
log = logging.getLogger('messages')
log.setLevel(logging.INFO)
ctaplog = logging.getLogger('messages.ctap')
ctaplog.setLevel(logging.INFO)
usbhid = logging.getLogger('messages.usbhid')
usbhid.setLevel(logging.INFO)

class CTAPHIDCMD(ABC):
    """Abstract CMD that provides core structure that all other requests
    and responses follow
    """

    def __init__(self, cid:bytes, cmd:ctap.constants.CTAP_CMD, bcnt, payload:bytes):
        self._cid = cid
        self._cmd = cmd
        self._bcnt = bcnt
        if self._bcnt  > ctap.constants.MAX_PAYLOAD:
            self._payload = payload
        else:
            self._payload = payload[:self._bcnt]
        ctaplog.debug("Created CTAPHID CMD: %s", self)
        self.remaining_bytes = self._bcnt - len(self._payload)


    def __str__(self):
        out = {}
        out["CID"]=self._cid.hex()
        out["CMD"]=self._cmd.name
        out["BCNT"]=self._bcnt
        out["payload"] = self._payload.hex()
        return json.dumps(out)

    def is_complete(self)->bool:
        """Checks if the message is complete or whether there
        are remaining continuation packets to be received.

        Returns:
            bool: True if the message is complete and ready to
                be processed, False if further packets are
                required
        """
        if self.remaining_bytes==0:
            return True
        return False

    def set_channel_id(self, channel_id:bytes):
        """Sets the channel id

        Args:
            channel_id (bytes): channel id
        """
        self._cid = channel_id
    def get_length(self)->int:
        """Gets the byte count length

        Returns:
            int: payload length
        """
        return self._bcnt

    def get_cmd(self)->ctap.constants.CTAP_CMD:
        """Gets the encoded command portion of the messages

        Returns:
            ctap.constants.CTAP_CMD: encoded command
        """
        return self._cmd

    def get_cid(self)->bytes:
        """Gets the channel id bytes

        Returns:
            bytes: channel id
        """
        return self._cid
    def get_payload(self)->bytes:
        """Gets the payload bytes portion of this message

        Returns:
            bytes: payload
        """
        return self._payload

    def get_hid_packets(self)->[HIDPacket]:
        """Returns a list of one or more HID packets that correctly
        encode the contents of this message. If it doesn't fit into
        a single Initialization packet it will be split into the
        appropriate continuation packets

        Returns:
            [HIDPacket]: array of HID packets
        """
        if self._bcnt>ctap.constants.MAX_PAYLOAD:
            usbhid.debug("Payload greater than single packet size, creating packets")
            packets = []
            packet = HIDInitializationPacket(self._cid,self._cmd,self._bcnt,
                self._payload[:ctap.constants.MAX_PAYLOAD])
            packets.append(packet)
            payload_index = ctap.constants.MAX_PAYLOAD
            for seq in range(128):
                end = min(self._bcnt-payload_index,ctap.constants.MAX_CONTINUATION_PAYLOAD)
                packets.append(HIDContinuationPacket(self._cid,seq,
                    self._payload[payload_index:payload_index+end]))
                payload_index = payload_index+end
                if payload_index == self._bcnt:
                    break
            usbhid.debug("Created %s HID Packets", len(packets))
            return packets
        usbhid.debug("Payload fits in a single HID Packet")
        packet = HIDInitializationPacket(self._cid,self._cmd,self._bcnt,self._payload)
        return [packet]

    @abstractmethod
    def verify(self):
        """Should be implemented by request messsages to perform verification of
        the submitted data to check compliance with the standard.

        This method is a void, that should complete without returning a value
        if everything is correct, or raise an exception when not valid
        """

    def append_continuation_packet(self,packet:HIDPacket):
        """Adds a continuation packet to original initialisation packet.

        This should be used to accumualted packets into a single
        complete message

        TODO Check handling of out of sequence packets

        Args:
            packet (HIDPacket): packet to add

        Raises:
            Exception: thrown when the packet to be appended is not
            a continuation packet
        """
        usbhid.debug("Appending continuation packet: %s", packet)
        if packet.CMDTYPE != ctap.constants.CMD_TYPE.CONTINUATION:
            raise Exception("Cannot append a non-continuation packet to a message")
        if self.remaining_bytes > ctap.constants.MAX_CONTINUATION_PAYLOAD:
            self._payload += packet.get_payload()
            self.remaining_bytes = self.remaining_bytes - ctap.constants.MAX_CONTINUATION_PAYLOAD
        else:
            self._payload += packet.get_payload()[:self.remaining_bytes]
            self.remaining_bytes = 0

    @staticmethod
    def create_message(packet: HIDPacket)->'CTAPHIDCMD':
        """Creates a message object of the appropriate type for a
        received HIDPacket

        Args:
            packet (HIDPacket): Initialization packet to create
                message from

        Raises:
            CTAPHIDException: thrown if the command is not known

        Returns:
            CTAPHIDCMD: Command message of appropriate type
        """
        if packet.get_cmd() == ctap.constants.CTAP_CMD.CTAPHID_INIT:
            return CTAPHIDInitRequest(packet)
        if packet.get_cmd() == ctap.constants.CTAP_CMD.CTAPHID_MSG:
            return CTAPHIDMsgRequest(packet)
        if packet.get_cmd() == ctap.constants.CTAP_CMD.CTAPHID_CBOR:
            return CTAPHIDCBORRequest(packet)
        if packet.get_cmd() == ctap.constants.CTAP_CMD.CTAPHID_WINK:
            return CTAPHIDWinkRequest(packet)
        if packet.get_cmd() == ctap.constants.CTAP_CMD.CTAPHID_CANCEL:
            return CTAPHIDCancelRequest(packet)
        if packet.get_cmd() == ctap.constants.CTAP_CMD.CTAPHID_PING:
            return CTAPHIDPingRequest(packet)
        raise CTAPHIDException(ctap.constants.CTAPHID_ERROR.ERR_INVALID_CMD, "Unknown Command: " + str(packet.get_cmd()))

class CTAPHIDMsgRequest(CTAPHIDCMD):
    """CTAP2 MSG Request

    Receives parameters as per the standard:

    """
    def __init__(self, packet: HIDInitializationPacket):
        super().__init__(packet.get_cid(),
            packet.get_cmd(),packet.get_length(),packet.get_payload())
        self._u2f_cmd = self._payload[0]


    def get_cmd_data(self)->bytes:
        """Gets the command data from the message

        Returns:
            bytes: command data
        """
        return self._payload[1:]

    def verify(self):
        """
        We don't verify the construction of requests
        """

class CTAPHIDMsgResponse(CTAPHIDCMD):
    """CTAP MSG Response consists of the following:

        Response at success
            CMD 	CTAPHID_MSG
            BCNT 	1..(n + 1)
            DATA 	U2F status code
            DATA + 1 	n bytes of data
    """
    def __init__(self,cid, U2F_Status,payload_data:bytes):
        payload = bytearray(len(payload_data)+1)
        payload[0] = U2F_Status
        payload[1:]=payload_data
        ctaplog.debug("Create initial MSG response %s",payload.hex())
        super().__init__(cid,ctap.constants.CTAP_CMD.CTAPHID_MSG,len(payload),payload)

    def verify(self):
        """
        We don't verify the construction of responses
        """



class CTAPHIDCancelRequest(CTAPHIDCMD):
    """CTAP HID Cancel Request. Consists of the following:

        Request
            CMD 	CTAPHID_CANCEL
            BCNT 	0
    """
    def __init__(self, packet: HIDInitializationPacket):
        super().__init__(packet.get_cid(),
            packet.get_cmd(),packet.get_length(),packet.get_payload())

    def verify(self):
        if len(self._payload)>0:
            raise CTAPHIDException(ctap.constants.CTAPHID_ERROR.ERR_INVALID_LEN, "Cancel request verification failed")


class CTAPHIDCancelResponse(CTAPHIDCMD):
    """CTAP Cancel Response consisting of:

        Response at success
            CMD 	CTAPHID_CANCEL
            BCNT 	0

    """
    def __init__(self,cid):
        ctaplog.debug("Create initial Cancel response")
        super().__init__(cid,ctap.constants.CTAP_CMD.CTAPHID_CANCEL,0,bytes(0))

    def verify(self):
        """
        We don't verify the construction of responses
        """

class CTAPHIDKeepAliveResponse(CTAPHIDCMD):
    """CTAP KeepAlive Response consists of:

        Response at success
            CMD 	CTAPHID_KEEPALIVE
            BCNT 	1
            DATA 	Status code

            The following status codes are defined
            STATUS_PROCESSING 	1 	The authenticator is still processing the current request.
            STATUS_UPNEEDED 	2 	The authenticator is waiting for user presence.
    """
    def __init__(self,cid,status_code:ctap.constants.CTAPHID_KEEPALIVE_STATUS):
        ctaplog.debug("Create Keep-alive response")
        super().__init__(cid,ctap.constants.CTAP_CMD.CTAPHID_KEEPALIVE,1,status_code.value)


    def verify(self):
        """
        We don't verify the construction of responses
        """

class CTAPHIDErrorResponse(CTAPHIDCMD):
    """CTAP Error Response consists of:

        Response at success
            CMD 	CTAPHID_ERROR
            BCNT 	1
            DATA 	Error code
    """
    def __init__(self,cid,error_code:ctap.constants.CTAPHID_ERROR):
        ctaplog.debug("Create initial Error response")
        super().__init__(cid,ctap.constants.CTAP_CMD.CTAPHID_ERROR,1,error_code.value)

    def verify(self):
        pass

class CTAPHIDWinkRequest(CTAPHIDCMD):
    """CTAP Wink Request consists of:

        Request
            CMD 	CTAPHID_WINK
            BCNT 	0
            DATA 	N/A
    """
    def __init__(self, packet: HIDInitializationPacket):
        super().__init__(packet.get_cid(),
            packet.get_cmd(),packet.get_length(),packet.get_payload())
        self.verify()

    def verify(self):
        if len(self._payload)>0:
            raise CTAPHIDException(ctap.constants.CTAPHID_ERROR.ERR_INVALID_LEN, "Wink request verification failed")

class CTAPHIDWinkResponse(CTAPHIDCMD):
    """CTAP Wink Response consists of:

        Response at success
            CMD 	CTAPHID_WINK
            BCNT 	0
            DATA 	N/A

    """
    def __init__(self,cid,payload_data:bytes):
        ctaplog.debug("Create initial WINK response %s",payload_data)
        super().__init__(cid,ctap.constants.CTAP_CMD.CTAPHID_WINK,len(payload_data),payload_data)

    def verify(self):
        """
        We don't verify the construction of responses
        """


class CTAPHIDPingRequest(CTAPHIDCMD):
    """CTAP Ping Reqeust consists of:

        Request
            CMD 	CTAPHID_PING
            BCNT 	0..n
            DATA 	n bytes
    """
    def __init__(self, packet: HIDInitializationPacket):
        super().__init__(packet.get_cid(),
            packet.get_cmd(),packet.get_length(),packet.get_payload())


    def verify(self):
        if not len(self._payload) == self._bcnt:
            raise CTAPHIDException(ctap.constants.CTAPHID_ERROR.ERR_INVALID_LEN, "Ping request verification failed")

class CTAPHIDPingResponse(CTAPHIDCMD):
    """CTAP Ping Response consists of:

        Response at success
            CMD 	CTAPHID_PING
            BCNT 	n
            DATA 	N bytes
    """
    def __init__(self,cid,payload_data:bytes):
        ctaplog.debug("Create initial PING response %s",payload_data)
        super().__init__(cid,ctap.constants.CTAP_CMD.CTAPHID_PING,len(payload_data),payload_data)

    def verify(self):
        """
        We don't verify the construction of responses
        """

class CTAPHIDLockRequest(CTAPHIDCMD):
    """CTAP Lock Reqeust consists of:

        Request
            CMD 	CTAPHID_PING
            BCNT 	1
            DATA 	Lock time in seconds 0..10. A value of 0 immediately releases the lock
    """
    def __init__(self, packet: HIDInitializationPacket):
        super().__init__(packet.get_cid(),
            packet.get_cmd(),packet.get_length(),packet.get_payload())
        self.verify()
        self._lock_time = lock_time = int.from_bytes( self.get_payload(),"big")

    def verify(self):
        if not len(self._payload) == self._bcnt:
            raise CTAPHIDException(ctap.constants.CTAPHID_ERROR.ERR_INVALID_LEN, "Lock request verification failed: payload != bcnt")
        if self.get_length() > 1:
            raise CTAPHIDException(ctap.constants.CTAPHID_ERROR.ERR_INVALID_LEN, "Lock request verification failed: length > 1")
        lock_time = int.from_bytes( self.get_payload(),"big")
        if lock_time < 0 or lock_time > 10:
            raise CTAPHIDException(ctap.constants.CTAPHID_ERROR.ERR_INVALID_PAR, "Lock request verification failed: lock_time")

    def get_lock_time(self)->int:
        """Get the lock time requested

        Raises:
            CTAPHIDException: Raised if the parameters are incorrect


        Returns:
            int: requested lock time between 0 and 10 seconds
        """
        return self._lock_time

class CTAPHIDLockResponse(CTAPHIDCMD):
    """CTAP Lock Response consists of:

        Response at success
            CMD 	CTAPHID_PING
            BCNT 	0
            DATA 	N/A
    """
    def __init__(self,cid):
        ctaplog.debug("Create initial Lock response ")
        super().__init__(cid,ctap.constants.CTAP_CMD.CTAPHID_LOCK,0,bytes(0))

    def verify(self):
        """
        We don't verify the construction of responses
        """



class CTAPHIDCBORRequest(CTAPHIDCMD):
    """CTAP CBOR Request consists of:

        Request
            CMD 	CTAPHID_CBOR
            BCNT 	1..(n + 1)
            DATA 	CTAP command byte
            DATA + 1 	n bytes of CBOR encoded data
    """
    def __init__(self, packet: HIDInitializationPacket):
        super().__init__(packet.get_cid(),
            packet.get_cmd(),packet.get_length(),packet.get_payload())
        self._ctap_cmd = self._payload[0]

    def get_cmd_data(self)->bytes:
        """Gets the command data, i.e. data after the command byte

        Returns:
            bytes: payload data excluding the command byte
        """
        return self._payload[1:]

    def verify(self):
        if self._bcnt != len(self._payload):
            raise CTAPHIDException(ctap.constants.CTAPHID_ERROR.ERR_INVALID_LEN, "CBOR request verification failed: payload != bcnt")
        try:
            ctap.constants.AUTHN_CMD(self._payload[0].to_bytes(1,"big"))
        except ValueError:
            if not (self._ctap_cmd >= \
                int.from_bytes(ctap.constants.AUTHN_CMD.AUTHN_VendorFirst.value,"big") \
                and self._ctap_cmd <= int.from_bytes(
                    ctap.constants.AUTHN_CMD.AUTHN_VendorLast.value,"big")):
                raise CTAPHIDException(ctap.constants.CTAPHID_ERROR.ERR_INVALID_PAR, "CBOR request verification failed: value error")



class CTAPHIDCBORResponse(CTAPHIDCMD):
    """CTAP CBOR Response consists of:

        Response at success
            CMD 	CTAPHID_MSG
            BCNT 	1..(n + 1)
            DATA 	CTAP status code
            DATA + 1 	n bytes of CBOR encoded data
    """
    def __init__(self,cid, CTAP_Status:ctap.constants.CTAP_STATUS_CODE,payload_data:bytes=bytes(0)):
        payload = bytearray(len(payload_data)+1)
        payload[0] = CTAP_Status.value[0]
        payload[1:]=payload_data
        ctaplog.debug("Create initial CBOR response %s",payload)
        super().__init__(cid,ctap.constants.CTAP_CMD.CTAPHID_CBOR,len(payload),payload)

    def verify(self):
        """
        We don't verify the construction of responses
        """

class CTAPHIDInitRequest(CTAPHIDCMD):
    """Init request

    """
    def __init__(self, packet: HIDInitializationPacket):
        super().__init__(packet.get_cid(),
            packet.get_cmd(),packet.get_length(),packet.get_payload())
        self.verify()

    def verify(self):
        if self.get_length()!= 8:
            raise Exception("Invalid init message length")


class CTAPHIDInitResponse(CTAPHIDCMD):
    """CTAP Init Response consists of:

        CMD 	CTAPHID_INIT
        BCNT 	17 (see note below)
        DATA 	8-byte nonce
        DATA+8 	4-byte channel ID
        DATA+12 	CTAPHID protocol version identifier
        DATA+13 	Major device version number
        DATA+14 	Minor device version number
        DATA+15 	Build device version number
        DATA+16 	Capabilities flags

    """
    CAPABILITY_WINK =b'\x01' #If set to 1, authenticator implements CTAPHID_WINK function
    CAPABILITY_CBOR =b'\x04' #If set to 1, authenticator implements CTAPHID_CBOR function
    CAPABILITY_NMSG =b'\x08' #If set to 1, authenticator DOES NOT implement CTAPHID_MSG function

    def __init__(self, version:AuthenticatorVersion):
        payload = bytearray(17) #17 bytes of data
        payload[12] = version.ctaphid_protocol_version
        payload[13] = version.major_version
        payload[14] = version.minor_version
        payload[15] = version.build_version
        payload[16] = CTAPHIDInitResponse.CAPABILITY_CBOR[0] \
            | CTAPHIDInitResponse.CAPABILITY_NMSG[0] | CTAPHIDInitResponse.CAPABILITY_WINK[0]
        ctaplog.debug("Capability value: %s",bin(payload[16]))
        ctaplog.debug("Creating initial response: %s",payload.hex())
        super().__init__(ctap.constants.BROADCAST_ID,
            ctap.constants.CTAP_CMD.CTAPHID_INIT,17,payload)

    def set_nonce(self, nonce:bytes):
        """Sets the nonce value of the message

        Args:
            nonce (bytes): nonce value
        """
        self._payload[0:8]=nonce

    def set_channel_id(self, channel_id:bytes):
        self._payload[8:12] = channel_id


    def set_protocol_version(self, version:int):
        """Sets the protocol version

        Args:
            version (int): protocol version will be converted to byte
        """
        self._payload[12] = version.to_bytes(1,"big")

    def set_capability_flag(self, flag):
        """Sets the capability flag

        Flag is the XOR of the CAPABILITY flags defined in the class
        Args:
            flag (int): flag to set
        """
        self._payload[18] = flag


    def verify(self):
        """
        We don't verify the construction of responses
        """
