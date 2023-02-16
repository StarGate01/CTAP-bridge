#!/usr/bin/env python3

import sys, signal, os
import argparse, time
import logging
from pathlib import Path

from hid.ctap import CTAPHID
from hid.usb import USBHID
from ctap.constants import AUTHN_CMD, CTAP_STATUS_CODE
from ctap.keep_alive import CTAPHIDKeepAlive
from bridge.datatypes import AuthenticatorVersion, BridgeException

from smartcard.System import readers
from smartcard.CardType import CardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnection import CardConnection
from smartcard.CardConnectionObserver import CardConnectionObserver
from smartcard.Exceptions import CardConnectionException

logging.basicConfig()
log = logging.getLogger('bridge')
log.setLevel(logging.DEBUG)

VERSION = AuthenticatorVersion(2,1,0,0)
KEEP_ALIVE_TIME_MS=15000

APDU_SELECT = [0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01]
APDU_SELECT_RESP = [0x46, 0x49, 0x44, 0x4F, 0x5F, 0x32, 0x5F, 0x30]
APDU_DESELECT = [0x80, 0x12, 0x01, 0x00]

scripts = Path(__file__).parent.resolve() / "scripts"

class FIDO2CardType(CardType):
    def matches(self, atr, reader=None): 
        if(not reader is None):
            try:
                conn = reader.createConnection()
                conn.connect()
                res, sw1, sw2 = conn.transmit(APDU_SELECT)
                conn.disconnect()
                return (sw1 == 0x90 and sw2 == 0x00 and res == APDU_SELECT_RESP)
            except:
                return False
        else:
            return False

class LoggingCardConnectionObserver(CardConnectionObserver):
    def update (self, cardconnection, ccevent):
        if(ccevent.type == "command"):
            log.debug("APDU CMD: DATA=%s", bytes(ccevent.args[0]).hex())
        elif(ccevent.type == "response"):
            log.debug("APDU RES: SW1=%s, SW2=%s, DATA=%s", hex(ccevent.args[1]), hex(ccevent.args[2]), bytes(ccevent.args[0]).hex())

class Bridge():
    def __init__(self):
        self._card = None
        self._usbdevice = None
        self._usbhid = None
        self._ctaphid = None
        self._shutdown_callback = None
     
    def shutdown(self, skip_callback=False):
        if(not self._usbhid is None):
            self._usbhid.shutdown()
        try:
            self._card.transmit(APDU_DESELECT)
            self._card.disconnect()
        except:
            pass
        log.debug("Tearing down USB device")
        os.system(scripts / "teardown_ctaphid.sh")
        time.sleep(1)
        if(not skip_callback):
            self._shutdown_callback()

    def start(self, card:CardConnection, shutdown_callback):
        self._shutdown_callback = shutdown_callback
        self._card = card
        self._card.addObserver(LoggingCardConnectionObserver())
        try:
            self._card.connect()
            self._card.transmit(APDU_SELECT)
        except:
            return False
        log.debug("Setting up USB device")
        os.system(scripts / "setup_ctaphid.sh")
        timeout = 0
        while not os.path.exists("/dev/ctaphid"):
            time.sleep(0.05)
            timeout += 1
            if(timeout >= 20):
                return False
        self._usbdevice = os.open("/dev/ctaphid", os.O_RDWR)
        self._usbhid = USBHID(self._usbdevice)
        self._ctaphid = CTAPHID(self._usbhid)
        self._ctaphid.set_authenticator(self)
        self._usbhid.set_listener(self._ctaphid)
        self._usbhid.start()
        return True

    def process_cbor(self, cbor_data:bytes, keep_alive: CTAPHIDKeepAlive, cid:bytes=None)->bytes:
        keep_alive.start(KEEP_ALIVE_TIME_MS)
        cmd = cbor_data[:1]
        log.debug("Received %s CBOR: %s", AUTHN_CMD(cmd).name, cbor_data.hex())

        res = bytes([])

        try:
            nfc_data = bytes([ 0x80, 0x10, 0x00, 0x00, len(cbor_data) ]) + cbor_data + bytes([ 0x00 ])
            self._card.transmit(APDU_SELECT)
        except Exception as e:
            log.error("Card error: %s, terminating connection", e)
            keep_alive.stop()
            raise BridgeException(CTAP_STATUS_CODE.CTAP1_ERR_OTHER, e)
  
        keep_alive.stop()
        return res

    def process_wink(self, payload:bytes, keep_alive: CTAPHIDKeepAlive)->bytes:
        log.info("WINK ;)")

    def get_version(self)->AuthenticatorVersion:
        return VERSION


bridge = Bridge()
term = False

def signal_handler(sig, frame):
    bridge.shutdown(True)
    sys.exit(0)
    
def monitor():
    request = CardRequest(timeout=None, cardType=FIDO2CardType())
    log.info("Waiting for FIDO2 card")
    card = request.waitforcard()
    log.info("Found FIDO2 card on %s", str(card.connection.getReader()))
    done = bridge.start(card.connection, monitor)
    if(not done):
        bridge.shutdown()

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    log.info('Press Ctrl+C to stop')
    monitor()
    signal.pause()
