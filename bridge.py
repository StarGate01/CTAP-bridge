#!/usr/bin/env python3

import sys, signal, os
import argparse, time, datetime
import logging
from pathlib import Path
import threading
from random import randrange

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
from smartcard.ExclusiveConnectCardConnection import ExclusiveConnectCardConnection

logging.basicConfig()
log = logging.getLogger('bridge')
log.setLevel(logging.DEBUG)

bridge = None
args = None

APDU_SELECT = [0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01]
APDU_SELECT_RESP = [0x46, 0x49, 0x44, 0x4F, 0x5F, 0x32, 0x5F, 0x30]
APDU_DESELECT = [0x80, 0x12, 0x01, 0x00]

scripts = Path(__file__).parent.resolve() / "scripts"

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
        elif(ccevent.type == "connect"):
            log.debug("Event: Card connected")
        elif(ccevent.type == "disconnect"):
            log.debug("Event: Card disconnected")
            bridge._card = None

class Bridge():
    def __init__(self):
        self._card = None
        self._usbdevice = None
        self._usbhid = None
        self._ctaphid = None
        self._timeout_last = datetime.datetime.now()
        self._timeout = threading.Thread(target=self.timeout_card)
        self._timeout_running = True
        self._timeout_paused = False
        self._timeout.daemon = True
        self._timeout.start()
        self._init_msg_last = datetime.datetime.now()
     
    def shutdown(self):
        self._timeout_running = False
        if(not self._usbhid is None):
            self._usbhid.shutdown()
        self.disconnect_card()
        log.info("Tearing down USB device")
        os.system(scripts / "teardown_ctaphid.sh")

    def start(self):
        log.info("Setting up USB device")
        os.system(scripts / "setup_ctaphid.sh")
        self._usbdevice = os.open("/dev/ctaphid", os.O_RDWR)
        self._usbhid = USBHID(self._usbdevice)
        self._ctaphid = CTAPHID(self._usbhid)
        self._ctaphid.set_authenticator(self)
        self._usbhid.set_listener(self._ctaphid)
        self._usbhid.start()
        return True

    def replug_usb(self):
        if (args.simreplug):
            dev = usb.core.find(idVendor=0x1209, idProduct=0x000C)
            if (not dev is None):
                log.info("Simulating USB re-plug, reloading kernel driver")
                dev.detach_kernel_driver(0)
                dev.attach_kernel_driver(0)

    def disconnect_card(self):
        self.replug_usb()
        try:
            if(not self._card is None):
                log.info("Disconnecting from card")
                self._card.connection.disconnect()
        except Exception as e:
            log.error("Cannot disconnect from card: %s", e)
        self._card = None

    def timeout_card(self):
        while(self._timeout_running):
            if(not self._timeout_paused):
                if ((datetime.datetime.now() - self._timeout_last).total_seconds() > args.idletimeout):
                    if(not self._card is None):
                        log.info("Card connection was idle too long, disconnecting.")
                        self.disconnect_card()
                        os.system(scripts / ("notify.sh 'FIDO2 NFC Token' 'The token was disconnected due to being unused' 'device.removed'"))
                time.sleep(1)

    def reset_timeout(self):
        self._timeout_last = datetime.datetime.now()

    def print_failing_cbor(self, cbor):
        if(len(cbor) > 1):
            log.debug("Failing CBOR command: %s, payload:", AUTHN_CMD(cbor[:1]).name)
            try:
                log.debug(json.dumps(cbor2.loads(cbor[1:]), indent=2, cls=BytesEncoder))
            except:
                log.debug("Decoding failed")

    def ensure_card(self):
        if (self._card == None):
            log.info("Transmit requested, watching for FIDO2 cards ...")
            request = CardRequest(timeout=args.scantimeout, cardType=FIDO2CardType())
            try:
                self._timeout_paused = True
                self._card = request.waitforcard()
                self.reset_timeout()
                self._timeout_paused = False
                log.info("Found FIDO2 card on %s", str(self._card.connection.getReader()))
                self._card.connection = ExclusiveConnectCardConnection(self._card.connection)
                self._card.connection.addObserver(LoggingCardConnectionObserver())
                self._card.connection.connect()
                self._card.connection.transmit(APDU_SELECT)
                os.system(scripts / ("notify.sh 'FIDO2 NFC Token' 'Found token on " + str(self._card.connection.getReader()) + "' 'device.added'"))
                return True
            except Exception as e:
                self._timeout_paused = False
                os.system(scripts / ("notify.sh 'FIDO2 NFC Token' 'No valid token was found in time.' 'device.removed'"))
                raise NoCardException(hresult=0, message="No valid card presented in time: " + str(e))
        return False

    def transmit_card(self, data):
        self.ensure_card()
        try:
            self._timeout_paused = True
            res = self._card.connection.transmit(data)
            self.reset_timeout()
            self._timeout_paused = False
            return res
        except Exception as e:
            self._timeout_paused = False
            log.error("Transmitting to card failed: %s", e)
            self.disconnect_card()
            raise e

    def process_cbor(self, cbor_data:bytes, keep_alive: CTAPHIDKeepAlive, cid:bytes=None)->bytes:
        keep_alive.start(200000 + randrange(5000))
        log.info("Transmitting CTAP command: %s", AUTHN_CMD(cbor_data[:1]).name)

        res = bytes([])
        err = None

        try:
            if (args.frag == "chaining"):
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
                    nfc_res, sw1, sw2 = self.transmit_card(nfc_data_out)

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
                            nfc_res, sw1, sw2 = self.transmit([0x80, 0xC0, 0x00, 0x00, sw2])
                            continue
                        # APDU error
                        if(not (sw1 == 0x90 and sw2 == 0x00)):
                            log.error("APDU error: sw1=%s, sw2=%s", sw1, sw2)
                            if(args.holderror):
                                log.error("Encountered APDU error response, halting")
                                self.print_failing_cbor(cbor_data)
                                self.shutdown()
                                sys.exit(1)
                            else:
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

            elif (args.frag == "extended"):
                # Extended APDUs
                nfc_data_out = [ 0x80, 0x10, 0x00, 0x00, 0x00 ]
                nfc_data_out += list(len(cbor_data).to_bytes(2, byteorder='big'))
                nfc_data_out += cbor_data
                nfc_data_out += [ 0x00, 0x00 ]

                # Transmit
                nfc_res, sw1, sw2 = self.transmit_card(nfc_data_out)

                # APDU error
                if(not (sw1 == 0x90 and sw2 == 0x00)):
                    log.error("APDU error: sw1=%s, sw2=%s", sw1, sw2)
                    if(args.holderror):
                        log.error("Encountered APDU error response, halting")
                        self.print_failing_cbor(cbor_data)
                        self.shutdown()
                        sys.exit(1)
                    else:
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
        self._init_msg_last = datetime.datetime.now()

        if(not err is None):
            self.print_failing_cbor(cbor_data)
            raise err
        else:
            if(not res is None and len(res) > 0):
                return res
            else:
                return bytes([])
               
    def process_wink(self, payload:bytes, keep_alive: CTAPHIDKeepAlive)->bytes:
        log.info("Wink request received")
        os.system(scripts / "notify.sh 'FIDO2 NFC Token' 'A service requests your attention.' 'device'")
        return bytes([])

    def process_initialization(self):
        log.info("Initialization request received")
        try:
            # New card found, simulate re-plug
            if (self.ensure_card()):
                self.replug_usb()
        except:
            pass
        if((datetime.datetime.now() - self._init_msg_last).total_seconds() > 5):
            os.system(scripts / ("notify.sh 'FIDO2 NFC Token' 'A service requests a connection to your token. Place your token on a reader.' 'device'"))
        self._init_msg_last = datetime.datetime.now()

    def get_version(self)->AuthenticatorVersion:
        return AuthenticatorVersion(1, 0, 0, 0)


def signal_handler(sig, frame):
    log.info("Shutting down")
    bridge.shutdown()
    sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = 'FIDO2 PC/SC CTAPHID Bridge')
    parser.add_argument('-f', '--fragmentation', nargs='?', dest='frag', type=str,
        const='chaining', default='chaining', choices=['chaining', 'extended'], 
        help='APDU fragmentation to use (default: chaining)')
    parser.add_argument('-e', '--exit-on-error', action='store_true', dest='holderror',
        help='Exit on APDU error responses (for fuzzing)')
    parser.add_argument('-nr', '--no-simulate-replug', action='store_false', dest='simreplug',
        help='Simulate USB re-plugging (for fuzzing)')
    parser.add_argument('-it', '--idle-timeout', nargs='?', dest='idletimeout', type=int, 
        const=20, default=20, 
        help='Idle timeout after which to disconnect from the card in seconds')
    parser.add_argument('-st', '--scan-timeout', nargs='?', dest='scantimeout', type=int, 
        const=30, default=30, 
        help='Time to wait for a token to be scanned')
    args = parser.parse_args()

    log.info("FIDO2 PC/SC CTAPHID Bridge running")
    log.info("Press Ctrl+C to stop")
    
    bridge = Bridge()
    bridge.start()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    signal.pause()
