"""Provides functionality to handle CTAP HID messages, decoding the
incoming packets and triggering their processing

Classes:

 * :class:`CTAPHID`
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
import os
import logging
from datetime import datetime, timedelta
import ctap.constants
from ctap.messages import (CTAPHIDCMD,CTAPHIDInitRequest,CTAPHIDInitResponse,
    CTAPHIDMsgRequest,CTAPHIDCBORRequest,CTAPHIDCBORResponse,
    CTAPHIDPingRequest,CTAPHIDPingResponse,CTAPHIDCancelRequest,CTAPHIDCancelResponse,
    CTAPHIDWinkRequest,CTAPHIDWinkResponse,CTAPHIDErrorResponse,CTAPHIDKeepAliveResponse,
    CTAPHIDLockRequest,CTAPHIDLockResponse)
from ctap.transaction import CTAPHIDTransaction
from ctap.exceptions import CTAPHIDException
from ctap.keep_alive import CTAPHIDKeepAlive
from bridge.datatypes import BridgeException
from hid.listeners import USBHIDListener
from hid.packets import HIDPacket
from hid.usb import USBHID

logging.basicConfig()
log = logging.getLogger('ctap')
log.setLevel(logging.INFO)
ctaplog = logging.getLogger('ctap.ctap')
ctaplog.setLevel(logging.INFO)
auth = logging.getLogger('ctap.auth')
auth.setLevel(logging.INFO)

class CTAPHID(USBHIDListener):
    """Acts a USBHIDListener, processing the incoming
    packets and sending them for processing

    """
    _BROADCAST_ID = b'\xff\xff\xff\xff'
    def __init__(self, usbhid:USBHID):
        """Instantiates a new CTAPHID object to act
        as a listener and writer for the USBHID provided

        Args:
            usbhid (USBHID): underlying USBHID device
        """
        self._usbhid = usbhid
        self._channels = {}
        self._transaction = None
        self._authenticator:'Bridge' = None
        self._keep_alive = CTAPHIDKeepAlive(self)
        self._channel_lock_id = None
        self._channel_lock_expires = None

    def set_authenticator(self, authenticator:'Bridge'):
        """Sets the authenticator assocaited with this CTAP instance

        Args:
            authenticator (Bridge): Authenticator to pass
                requests on to
        """
        self._authenticator=authenticator
        log.debug("Authenticator set: %s",self._authenticator )

    def channel_exists(self, channel_id:bytes)->bool:
        """Checks if a channel alreay exists

        Args:
            channel_id (bytes): channel id to check

        Returns:
            [bool]: True if channel exists, False if not
        """
        return channel_id in self._channels

    def get_channel(self, channel_id:bytes)->CTAPHIDTransaction:
        """Gets the Transaction assocaited with the channel ID

        Currently there is only one transaction allowed, so
        channel_id is redundant. However, if concurrent
        processing is developed this will be required

        Args:
            channel_id (bytes): channel ID to lookup

        Returns:
            CTAPHIDTransaction: transaction associated with the channel
        """
        return self._transaction
        #if not channel_id in self._channels:
        #    raise ChannelNotFoundException("Channel not found")
        #return self._channels.get(channel_id)

    def received_packet(self, packet: HIDPacket):
        """Called when packet is received

        Args:
            packet (HIDPacket): received packet
        """
        if not self._channel_lock_id is None and packet.get_cid() != self._channel_lock_id:
            if datetime.now() < self._channel_lock_expires:
                ctaplog.warning("Error channel is locked")
                self.send_error_response(CTAPHIDErrorResponse(self._transaction.request.get_cid(),
                    ctap.constants.CTAPHID_ERROR.ERR_CHANNEL_BUSY))
                return
            ctaplog.info("Lock has expired, clearing")
            self._channel_lock_expires = None
            self._channel_lock_id = None

        if packet.CMDTYPE == ctap.constants.CMD_TYPE.INITIALIZATION:
            log.info("Received initialization packet")

            ctap_msg = CTAPHIDCMD.create_message(packet)
            ctaplog.debug("Received initialization packet: %s", ctap_msg)
            self._keep_alive.set_cid(ctap_msg.get_cid())
            if (not self._transaction is None and
                not ctap_msg.get_cid() == self._transaction.get_cid()):
                self.send_error_response(CTAPHIDErrorResponse(ctap_msg.get_cid(),
                    ctap.constants.CTAPHID_ERROR.ERR_CHANNEL_BUSY), True)
            else:
                self._transaction = CTAPHIDTransaction(ctap_msg.get_cid())
                self._transaction.set_request(ctap_msg)
                ctaplog.debug("Created transaction: %s", self._transaction)
            self._authenticator.process_initialization()
        elif packet.CMDTYPE == ctap.constants.CMD_TYPE.CONTINUATION:
            ctaplog.debug("Received Continuation Packet - seqNo: %s", packet.get_sequence())
            self._transaction.request.append_continuation_packet(packet)

        #If we have finished receiving packets, process the request
        if self._transaction.request.is_complete():
            try:
                self._transaction.request.verify()
                ctaplog.debug("Message is complete: %s", self._transaction)
                if self._transaction.request.get_cmd() == ctap.constants.CTAP_CMD.CTAPHID_INIT:
                    self.process_init_request(self._transaction.request)
                elif self._transaction.request.get_cmd() == ctap.constants.CTAP_CMD.CTAPHID_MSG:
                    self.process_msg_request(self._transaction.request)
                elif self._transaction.request.get_cmd() == ctap.constants.CTAP_CMD.CTAPHID_CBOR:
                    self.process_cbor_request(self._transaction.request)
                elif self._transaction.request.get_cmd() == ctap.constants.CTAP_CMD.CTAPHID_PING:
                    self.process_ping_request(self._transaction.request)
                elif self._transaction.request.get_cmd() == ctap.constants.CTAP_CMD.CTAPHID_CANCEL:
                    self.process_cancel_request(self._transaction.request)
                elif self._transaction.request.get_cmd() == ctap.constants.CTAP_CMD.CTAPHID_WINK:
                    self.process_wink_request(self._transaction.request)
                elif self._transaction.request.get_cmd() == ctap.constants.CTAP_CMD.CTAPHID_LOCK:
                    self.process_lock_request(self._transaction.request)
            except CTAPHIDException as exception:
                ctaplog.error("Exception processing CTAP HID",exc_info=True)
                self.send_error_response(CTAPHIDErrorResponse(self._transaction.request.get_cid(),
                    exception.get_error_code()))

        else:
            ctaplog.debug("Message incomplete remaining bytes: %s",
                self._transaction.request.remaining_bytes)

    def send_error_response(self, msg_response: CTAPHIDErrorResponse, is_init_error:bool=False):
        """Sends an error response. Either sends the error as part of a transaction
        or in a temporary transaction

        is_init_error signifies whether the error occured during the CTAP INIT call, if
        so there might not be a transaction, for example, responding with a channel
        busy error. If set to True this will create a new temp transaction to send
        the error message in and not close the existing transaction

        Args:
            msg_response (CTAPHIDErrorResponse): Error response to send
            is_init_error (bool, optional): if set. Defaults to False.
        """
        ctaplog.debug("Sending error response: %s", msg_response)

        if not self._transaction is None and not is_init_error:
            self._transaction.error(msg_response)
            self.send_response(self._transaction)
        else:
            temp_transaction = CTAPHIDTransaction(msg_response.get_cid())
            temp_transaction.error(msg_response)
            self.send_response(temp_transaction)

    def send_keep_alive_response(self, msg_response: CTAPHIDKeepAliveResponse):
        """Sends a keep alive response outside of the normal request-response
        associated with a transaction. Creates a temp transaction to hold
        the keep alive response

        Args:
            msg_response (CTAPHIDKeepAliveResponse): keep alive response to send
        """
        temp_transaction = CTAPHIDTransaction(msg_response.get_cid())
        temp_transaction.keep_alive(msg_response)
        self.send_response(temp_transaction)

    def process_cancel_request(self, msg_request: CTAPHIDCancelRequest):
        """processes a cancel request

        Args:
            msg_request (CTAPHIDCancelRequest): cancel request to process
        """
        ctaplog.debug("Received cancel request: %s", msg_request)
        if not self.channel_exists(msg_request.get_cid()):
            self.send_error_response(CTAPHIDErrorResponse(msg_request.get_cid(),
                ctap.constants.CTAPHID_ERROR.ERR_INVALID_CHANNEL))
        else:
            if msg_request.is_complete():
                response = CTAPHIDCancelResponse(self._transaction.get_cid())
                self._transaction.cancel(response)
                self.send_response(self._transaction)

    def process_wink_request(self, msg_request: CTAPHIDWinkRequest):
        """Processes a wink request. Without a UI this will not
        do anything.

        Args:
            msg_request (CTAPHIDWinkRequest): wink request to process
        """
        ctaplog.debug("Received Wink request: %s", msg_request)
        if not self.channel_exists(msg_request.get_cid()):
            self.send_error_response(CTAPHIDErrorResponse(msg_request.get_cid(),
                ctap.constants.CTAPHID_ERROR.ERR_INVALID_CHANNEL))
        else:
            transaction  = self.get_channel(msg_request.get_cid())
            if not self._authenticator is None:
                try:
                    resp = self._authenticator.process_wink(msg_request.get_payload(),
                        self._keep_alive)
                    transaction.set_response(CTAPHIDWinkResponse(self._transaction.get_cid(),resp))
                    self.send_response(transaction)
                except BridgeException as exc:
                    auth.error("Exception from authenticator: %s", exc)
                    self.send_error_response(CTAPHIDCBORResponse(msg_request.get_cid(),
                        exc.get_error_code()))

    def process_lock_request(self, msg_request: CTAPHIDLockRequest):
        """Processes a lock request.

        Args:
            msg_request (CTAPHIDLockRequest): lock request to process
        """
        ctaplog.debug("Received Lock request: %s", msg_request)
        if not self.channel_exists(msg_request.get_cid()):
            self.send_error_response(CTAPHIDErrorResponse(msg_request.get_cid(),
                ctap.constants.CTAPHID_ERROR.ERR_INVALID_CHANNEL))
        else:
            transaction  = self.get_channel(msg_request.get_cid())
            if msg_request.is_complete():
                if self._channel_lock_id is None or self._channel_lock_id == msg_request.get_cid():
                    if msg_request.get_lock_time() == 0:
                        self._channel_lock_expires = None
                        self._channel_lock_id = None
                    else:
                        self._channel_lock_expires = \
                            datetime.now() + timedelta(seconds=msg_request.get_lock_time())
                        ctaplog.debug("Set channel lock expires at: %s", self._channel_lock_expires)
                response = CTAPHIDLockResponse(self._transaction.get_cid())
                transaction.set_response(response)
                self.send_response(transaction)

    def process_ping_request(self, msg_request: CTAPHIDPingRequest):
        """Process ping request

        Args:
            msg_request (CTAPHIDPingRequest): ping request to process
        """
        ctaplog.debug("Received ping request: %s", msg_request)
        if not self.channel_exists(msg_request.get_cid()):
            self.send_error_response(CTAPHIDErrorResponse(msg_request.get_cid(),
                ctap.constants.CTAPHID_ERROR.ERR_INVALID_CHANNEL))
        else:
            transaction  = self.get_channel(msg_request.get_cid())
            if msg_request.is_complete():
                response = CTAPHIDPingResponse(self._transaction.get_cid(),
                    transaction.request.get_payload())
                transaction.set_response(response)
                self.send_response(transaction)

    def process_cbor_request(self, msg_request: CTAPHIDCBORRequest):
        """Process a CBOR request. This is the core part of the processing
        since most message are CBOR encoded messages

        Args:
            msg_request (CTAPHIDCBORRequest): CBOR message to process
        """
        ctaplog.debug("Received CBOR request: %s", msg_request)
        if not self.channel_exists(msg_request.get_cid()):
            self.send_error_response(CTAPHIDErrorResponse(msg_request.get_cid(),
                ctap.constants.CTAPHID_ERROR.ERR_INVALID_CHANNEL))
        else:

            transaction  = self.get_channel(msg_request.get_cid())

            if not self._authenticator is None:
                self._keep_alive.set_cid(msg_request.get_cid())
                self._keep_alive.start(20000)
                try:
                    resp = self._authenticator.process_cbor(msg_request.get_payload(),
                        self._keep_alive)
                    transaction.set_response(CTAPHIDCBORResponse(self._transaction.get_cid(),
                        ctap.constants.CTAP_STATUS_CODE.CTAP2_OK,resp))
                    self.send_response(transaction)
                except BridgeException as exc:
                    auth.error("Exception from authenticator: %s", exc)
                    self.send_error_response(CTAPHIDCBORResponse(msg_request.get_cid(),
                        exc.get_error_code()))
                except CTAPHIDException as exc:
                    ctaplog.error("Exception processing CTAP HID: %s", exc)
                    self.send_error_response(CTAPHIDErrorResponse(msg_request.get_cid(),
                        exc.get_error_code()))
                self._keep_alive.stop()

    def process_msg_request(self, msg_request: CTAPHIDMsgRequest):
        """Process a MSG request. This is currently not implemented

        MSG requests are backward compatible CTAP1/U2F messages which
        has not been implemented in the authenticator

        Args:
            msg_request (CTAPHIDMsgRequest): MSG request to process
        """
        ctaplog.debug("Received MSG request: %s", msg_request)
        if not self.channel_exists(msg_request.get_cid()):
            self.send_error_response(CTAPHIDErrorResponse(msg_request.get_cid(),
                ctap.constants.CTAPHID_ERROR.ERR_INVALID_CHANNEL))
        else:
            self.send_error_response(CTAPHIDErrorResponse(msg_request.get_cid(),
                ctap.constants.CTAPHID_ERROR.ERR_OTHER))


    def process_init_request(self, init_request: CTAPHIDInitRequest):
        """Process an INIT request the first request received that is
        used to create a channel

        Args:
            init_request (CTAPHIDInitRequest): INIT request to process
        """
        ctaplog.debug("Received INIT request: %s", init_request)
        if init_request.get_cid() == self._BROADCAST_ID:
            channel_id = self.create_channel_id()
            response = CTAPHIDInitResponse(self._authenticator.get_version())
            response.set_nonce(init_request.get_payload())
            response.set_channel_id(channel_id)
            self._transaction.set_response(response)
            self.send_response(self._transaction)
        else:
            ctaplog.info("Channel exists, resync channel")
            self._transaction.reset()
            response = CTAPHIDInitResponse(self._authenticator.get_version())
            response.set_nonce(init_request.get_payload())
            response.set_channel_id(init_request.get_cid())
            self._transaction.set_response(response)
            self.send_response(self._transaction)

    def response_sent(self, transaction: CTAPHIDTransaction):
        """Received when a response has been set and the
        transaction can be reset.

        Args:
            transaction (CTAPHIDTransaction): Transaction whose
                response was sent and can now be reset
        """
        ctaplog.debug("Response sent. Resetting transaction to idle state - isError:%s, isKeepAlive: %s, %s",
            transaction.is_error_transaction(), transaction.is_keep_alive_transaction(), transaction)
        if transaction == self._transaction:
            #Return to idle state
            self._transaction.reset()
            self._transaction = None
        else:
            transaction.reset()

    def create_channel_id(self)->bytes:
        """Creates a random channel ID

        Raises:
            Exception: Raised if no unique channel can be
                generated

        Returns:
            bytes: 4 channel ID bytes
        """
        channel_id = bytes(os.urandom(4))
        runaway_counter=0
        while channel_id in self._channels:
            runaway_counter += 1
            channel_id = bytes(os.urandom(4))
            if runaway_counter>1000:
                raise Exception(
                    "Attempted to generate a channel id 1000 times and failed to find a unique ID")
        self._channels[channel_id]=None
        return channel_id

    def send_response(self, transaction: CTAPHIDTransaction):
        """Sends a response by adding the transaction to the
        write queue of the USB HID device.

        Args:
            transaction (CTAPHIDTransaction): transaction whose response should be sent
        """
        self._usbhid.add_transaction_to_queue(transaction)
