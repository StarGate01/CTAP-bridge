#!/usr/bin/env python3

import sys, signal, os
import argparse, time
import logging
from pathlib import Path
import threading

import usb.core
import usb.util

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
from smartcard.Exceptions import CardConnectionException, NoCardException, CardRequestTimeoutException

logging.basicConfig()
log = logging.getLogger('bridge')
log.setLevel(logging.DEBUG)

VERSION = AuthenticatorVersion(1,0,0,0)
KEEP_ALIVE_TIME_MS=15000

APDU_SELECT = [0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01]
APDU_SELECT_RESP = [0x46, 0x49, 0x44, 0x4F, 0x5F, 0x32, 0x5F, 0x30]
APDU_DESELECT = [0x80, 0x12, 0x01, 0x00]

scripts = Path(__file__).parent.resolve() / "scripts"
monitor_paused = threading.Lock()

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
     
    def shutdown(self):
        if(not self._usbhid is None):
            self._usbhid.shutdown()
        try:
            self._card.transmit(APDU_DESELECT)
            self._card.disconnect()
        except:
            pass
        log.debug("Tearing down USB device")
        os.system(scripts / "teardown_ctaphid.sh")

    def start(self):
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

    def set_card(self, card:CardConnection):
        self._card = card
        self._card.addObserver(LoggingCardConnectionObserver())
        self._card.connect()
        self._card.transmit(APDU_SELECT)
        dev = usb.core.find(idVendor=0x1209, idProduct=0x000C)
        if (not dev is None):
            log.info("Simulating USB re-plug, reloading kernel driver")
            dev.detach_kernel_driver(0)
            dev.attach_kernel_driver(0)
        else:
            raise Exception("USB interface not found")

    def process_cbor(self, cbor_data:bytes, keep_alive: CTAPHIDKeepAlive, cid:bytes=None)->bytes:
        keep_alive.start(KEEP_ALIVE_TIME_MS)
        cmd = cbor_data[:1]
        log.debug("Received %s CBOR: %s", AUTHN_CMD(cmd).name, cbor_data.hex())

        res = bytes([])
        err = None

        try:
            if(self._card is None):
                raise NoCardException(hresult=0, message="No card connected yet")

            nfc_data = bytes([ 0x80, 0x10, 0x00, 0x00, len(cbor_data) ]) + cbor_data + bytes([ 0x00 ])

            self._card.transmit(APDU_SELECT)
            
        except Exception as e:
            log.error("Card error: %s", e)
            err = e

        keep_alive.stop()

        if(not err is None):
            raise BridgeException(CTAP_STATUS_CODE.CTAP1_ERR_OTHER, err)
        else:
            return res

    def process_wink(self, payload:bytes, keep_alive: CTAPHIDKeepAlive)->bytes:
        log.info("WINK ;)")
        res = bytes([])
        return res

    def get_version(self)->AuthenticatorVersion:
        return VERSION


bridge = Bridge()
monitor_running = False

def signal_handler(sig, frame):
    monitor_paused.release()
    monitor_running = False
    bridge.shutdown()
    sys.exit(0)

def monitor():
    log.info("Monitoring for FIDO2 cards")
    request = CardRequest(timeout=1, cardType=FIDO2CardType())
    card = None
    while(monitor_running):
        if(monitor_paused.acquire(timeout=0.5, blocking=True)):
            try:
                card = request.waitforcard()
                log.info("Found FIDO2 card on %s", str(card.connection.getReader()))
                bridge.set_card(card.connection)
            except:
                try:
                    monitor_paused.release()
                except RuntimeError:
                    pass
        else:
            if(not card is None):
                try:
                    card.connection.connect()
                except:
                    log.info("Card connection broke")
                    log.info("Monitoring for FIDO2 cards")
                    try:
                        monitor_paused.release()
                    except RuntimeError:
                        pass

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    log.info('Press Ctrl+C to stop')
    bridge.start()
    monitor_thread = threading.Thread(target=monitor)
    monitor_running = True
    monitor_thread.daemon = True
    monitor_thread.start()
    signal.pause()
