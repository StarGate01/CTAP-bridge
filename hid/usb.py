"""Provides class to interface with USB devices

    Classes:

 * :class:`USBHID`
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
import threading

import os
import logging

from queue import Queue
from hid.ctap import HIDPacket, CTAPHIDTransaction
from hid.listeners import USBHIDListener

logging.basicConfig()
log = logging.getLogger('usb')
log.setLevel(logging.INFO)
usblog = logging.getLogger('usb.usbhid')
usblog.setLevel(logging.INFO)

class USBHID:
    """Provides a class to open and read from a USB device
    """
    def __init__(self, device):
        self._device = device
        self._is_listening = False
        self._listener = None
        self._running = False
        self._packets = {}
        self._write_queue = Queue()
        self._read_thread = None
        self._write_thread = None

    def start(self):
        """Starts threads to listen to and write to the underlying
        usb device. Threads are started as daemon threads so do not
        need to be explicitly stopped.
        """
        if self._is_listening:
            raise Exception("start_listening can only be called once")
        self._is_listening = True
        self._running = True
        self._read_thread = threading.Thread(target=self._listen)
        self._read_thread.daemon = True
        self._read_thread.start()
        self._write_thread = threading.Thread(target=self._write)
        self._write_thread.daemon = True
        self._write_thread.start()
        log.info("Started listening threads")

    def add_transaction_to_queue(self, transaction: CTAPHIDTransaction):
        """Adds a transaction to the write queue. When written the
        response will be written and transaction cleared

        Args:
            transaction (CTAPHIDTransaction): transaction to be written
        """
        log.debug("Transaction added to write queue: %s",transaction)
        self._write_queue.put(transaction)

    def set_listener(self, listener:USBHIDListener):
        """Sets the listener for this device. Originally intended to
        support multiple listeners, due to restrictions in CTAP this
        was no longer needed, so only a single listener can be set.

        Args:
            listener (USBHIDListener): class that implements the listener
                functions
        """
        log.debug("listener added %s", listener)
        self._listener = listener

    def remove_listener(self, listener:USBHIDListener):
        """Removes the specified listener - the listener argument is
        redundant due to the single listener restriction, but remains
        in case furture development allows multiple listeners/authenticators

        Args:
            listener (USBHIDListener): listener to remove, or None
        """
        log.debug("listener removed %s", listener)
        self._listener = None

    def shutdown(self):
        """Shutdown the device
        """
        self._running = False
        log.info("Shutdown called")


    def _write(self):
        """Write method called by the write thread. This method
        enters an infinite loop waiting for items to be added to
        the write queue and then writing them. This should only
        be called from a dedicated write thread, otherwise it will
        hang the calling thread.
        """
        while self._running:
            transaction = self._write_queue.get()
            usblog.debug("Got transaction to write %s",transaction)
            packets = transaction.response.get_hid_packets()
            for packet in packets:
                usblog.debug("\twriting bytes from packet: %s", packet.get_bytes().hex())
                try:
                    os.write(self._device, packet.get_bytes())
                except BrokenPipeError:
                    log.error("Broken pipe")
                    self.shutdown()
            usblog.debug("Finished writing transaction")
            self._listener.response_sent(transaction)


    def _listen(self):
        """listen mthod called by the listen thread. This method
        enters an infinite loop waiting for bytes from the USB
        device, and then passing them on to the listener.

        TODO this not as concurrent as it could be, listener should be called
        in a way that doesn't block this thread
        """
        while self._running:
            try:
                hid_packet = HIDPacket.from_bytes(os.read(self._device,64))
                #hid_packet = HIDPacket.from_bytes(self._device.read(64))
                usblog.debug("Received hid packet: %s",hid_packet)
                self._listener.received_packet(hid_packet)
            except Exception:
                log.error("Exception reading from device", exc_info=True)
        log.info("USBHID no longer listening")
