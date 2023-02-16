"""Keep alive object that is created with each request to
faciliate the sending of keep alive messages

Classes:

 * :class:`CTAPHIDKeepAlive`
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
import logging
import time
from ctap.messages import CTAPHIDKeepAliveResponse
import ctap.constants

logging.basicConfig()
log = logging.getLogger('keep_alive')
log.setLevel(logging.INFO)

class CTAPHIDKeepAlive():
    """Class to automatically send keep-alive messages during the processing of a
    request
    """
    def __init__(self, ctaphid:'CTAPHID'):
        """Creates a new keep alive instance. This won't do anying unless
        start is called, leaving it up to the authenticator to decide
        whether to send keep-alive messages or not

        Args:
            ctaphid (CTAPHID): underlying CTAP HID device to send keep alive
                messages with
        """
        self._interval = (1/1000)*1000
        self._ctaphid = ctaphid
        self._cid = None
        self._status = ctap.constants.CTAPHID_KEEPALIVE_STATUS.STATUS_PROCESSING
        self._running = False
        self._keep_alive_thread = None
        self._elapsed =0
        self._max = 0

    def set_cid(self, cid:bytes):
        """Sets the channel ID

        Args:
            cid (bytes): channel id bytes
        """
        self._cid = cid

    def start(self, max_val=120000):
        """starts the keep alive sender. This will send keep-alive messages
        at interval set in _interval which is every second. It will keep
        sending them until the max_val is reached and will then stop

        Args:
            max_val (int, optional): maximum period for which keep alive
                messages should be sent. Defaults to 120000 milliseconds/
                120 seconds/2 minutes.

        Raises:
            Exception: thrown if no channel has been set
        """
        if self._cid is None:
            raise Exception("Keep-alive channel not set")
        log.info("Start keep-alive called")
        self._max = max_val/1000
        self._keep_alive_thread = threading.Thread(target=self._keep_alive)
        self._running = True
        self._keep_alive_thread.daemon = True
        self._keep_alive_thread.start()

    def stop(self):
        """Stop the keep alive sender. This will stop after the next interval
        has expired
        """
        self._running = False

    def update_status(self, status:ctap.constants.CTAPHID_KEEPALIVE_STATUS):
        """Change the status being sent in the keep-alive message

        Args:
            status (ctap.constants.CTAPHID_KEEPALIVE_STATUS): new status to send
        """
        log.debug("Keep-alive status updated")
        self._status = status
        self._send_keep_alive()

    def _send_keep_alive(self):
        """Sends the keep alive message
        """
        self._ctaphid.send_keep_alive_response(CTAPHIDKeepAliveResponse(self._cid,self._status))

    def _keep_alive(self):
        """Function that runs in the thread to trigger the keep-alive messages
        """
        while self._running:
            self._send_keep_alive()
            time.sleep(self._interval)
            self._elapsed = self._elapsed + self._interval
            if self._elapsed > self._max:
                log.warning("Max keep-alive exceeded - will stop")
                self._running = False
        log.info("Keep-alive ended")
        self._cid = None
