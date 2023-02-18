#!/usr/bin/env python3

import sys, signal, os
import argparse, time
import logging
from pathlib import Path
import threading

import cbor2, json

import usb.core
import usb.util

from hid.ctap import CTAPHID
from hid.usb import USBHID
from ctap.constants import AUTHN_CMD, CTAP_STATUS_CODE
from ctap.exceptions import CTAPHIDException
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
KEEP_ALIVE_TIME_MS=12000000

chaining = True
APDU_SELECT = [0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01]
APDU_SELECT_RESP = [0x46, 0x49, 0x44, 0x4F, 0x5F, 0x32, 0x5F, 0x30]
APDU_DESELECT = [0x80, 0x12, 0x01, 0x00]

scripts = Path(__file__).parent.resolve() / "scripts"
monitor_paused = threading.Lock()

class BytesEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return "h'" + obj.hex()
        return json.JSONEncoder.default(self, obj)

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
        log.info("Tearing down USB device")
        os.system(scripts / "teardown_ctaphid.sh")

    def start(self):
        log.info("Setting up USB device")
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
        log.info("Transmitting CTAP command: %s", AUTHN_CMD(cbor_data[:1]).name)

        res = bytes([])
        err = None

        try:
            if(self._card is None):
                raise NoCardException(hresult=0, message="No card connected yet")

            if chaining:
                # Chaining out
                data_out_index = 0
                data_out_remain = len(cbor_data)
                while(data_out_remain > 0):
                    nfc_data_out = [ 0x80, 0x10, 0x00, 0x00 ]
                    data_out_size = data_out_remain
                    data_out_index_prev = data_out_index
                    if (data_out_remain > 255):
                        data_out_size = 255
                        data_out_remain -= 255
                        data_out_index += 255
                        nfc_data_out[0] = 0x90
                    else:
                        # Last chunk
                        data_out_remain = 0
                    nfc_data_out += [ data_out_size ]
                    nfc_data_out += cbor_data[data_out_index_prev:(data_out_index_prev + data_out_size)]
                    nfc_data_out += [ 0x00 ]

                    # Transmit
                    nfc_res, sw1, sw2 = self._card.transmit(nfc_data_out)

                    # Chaining in
                    data_in_done = False
                    data_in_first = True
                    ctap_err = CTAP_STATUS_CODE.CTAP1_ERR_OTHER
                    while(not data_in_done):
                        # More data to retrieve
                        if(sw1 == 0x61):
                            if(data_in_first):
                                data_in_first = False
                                ctap_err = CTAP_STATUS_CODE(nfc_res[0].to_bytes(1, byteorder="little"))
                                res += bytes(nfc_res[1:])
                            else:
                                res += bytes(nfc_res)
                            nfc_res, sw1, sw2 = self._card.transmit([0x80, 0xC0, 0x00, 0x00, sw2])
                            continue
                        # APDU error
                        if(not (sw1 == 0x90 and sw2 == 0x00)):
                            log.error("APDU error: sw1=%s, sw2=%s", sw1, sw2)
                            raise BridgeException(CTAP_STATUS_CODE.CTAP1_ERR_OTHER, "Unexpected APDU response status code")
                        else:
                            # Success
                            data_in_done = True
                            if(data_in_first):
                                ctap_err = CTAP_STATUS_CODE.CTAP2_OK
                                if(len(nfc_res) > 0):
                                    ctap_err = CTAP_STATUS_CODE(nfc_res[0].to_bytes(1, byteorder="little"))
                            if(not ctap_err is CTAP_STATUS_CODE.CTAP2_OK):
                                log.error("CTAP error: %s", ctap_err)
                                raise CTAPHIDException(ctap_err)
                            else:
                                if(len(nfc_res) > 0):
                                    if(data_in_first):
                                        res += bytes(nfc_res[1:])
                                    else:
                                        res += bytes(nfc_res)
            else:
                # Extended APDUs
                nfc_data_out = [ 0x80, 0x10, 0x00, 0x00, 0x00 ]
                nfc_data_out += list(len(cbor_data).to_bytes(2, byteorder='big'))
                nfc_data_out += cbor_data
                nfc_data_out += [ 0x00, 0x00 ]

                # Transmit
                nfc_res, sw1, sw2 = self._card.transmit(nfc_data_out)

                # APDU error
                if(not (sw1 == 0x90 and sw2 == 0x00)):
                    log.error("APDU error: sw1=%s, sw2=%s", sw1, sw2)
                    raise BridgeException(CTAP_STATUS_CODE.CTAP1_ERR_OTHER, "Unexpected APDU response status code")
                else:
                    # Success
                    ctap_err = CTAP_STATUS_CODE.CTAP2_OK
                    if(len(nfc_res) > 0):
                        ctap_err = CTAP_STATUS_CODE(nfc_res[0].to_bytes(1, byteorder="little"))
                    if(not ctap_err is CTAP_STATUS_CODE.CTAP2_OK):
                        log.error("CTAP error: %s", ctap_err)
                        raise CTAPHIDException(ctap_err)
                    else:
                        res += bytes(nfc_res[1:])

        except BridgeException as e:
            err = e
        except CTAPHIDException as e:
            err = e
        except Exception as e:
            log.error("Card error: %s", e)
            err = BridgeException(CTAP_STATUS_CODE.CTAP1_ERR_OTHER, err)

        keep_alive.stop()

        if(not err is None):
            if(len(cbor_data) > 1):
                log.debug("Failing CBOR command: %s, payload:", AUTHN_CMD(cbor_data[:1]).name)
                log.debug(json.dumps(cbor2.loads(cbor_data[1:]), indent=2, cls=BytesEncoder))
            raise err
        else:
            return res

    def process_wink(self, payload:bytes, keep_alive: CTAPHIDKeepAlive)->bytes:
        log.info("WINK received")
        os.system(scripts / "notify.sh 'FIDO2 NFC Token' 'A service requests your attention.' 'device'")
        return bytes([])

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
                os.system(scripts / ("notify.sh 'FIDO2 NFC Token' 'Found token on " + str(card.connection.getReader()) + "' 'device.added'"))
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
                except Exception as e:
                    log.info("Card connection broke: %s", e)
                    log.info("Monitoring for FIDO2 cards")
                    try:
                        monitor_paused.release()
                    except RuntimeError:
                        pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = 'FIDO2 PC/SC CTAPHID Bridge')
    parser.add_argument('-f', '--fragmentation', nargs='?', dest='frag', type=str,
        const='chaining', default='chaining', choices=['chaining', 'extended'], 
        help='APDU fragmentation to use (default: chaining)')
    args = parser.parse_args()
    chaining = (args.frag == "chaining")

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    log.info('Press Ctrl+C to stop')
    bridge.start()
    monitor_thread = threading.Thread(target=monitor)
    monitor_running = True
    monitor_thread.daemon = True
    monitor_thread.start()
    signal.pause()
