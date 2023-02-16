#!/usr/bin/env python3

import sys, signal, os
import argparse, time
import logging
from pathlib import Path

from hid.ctap import CTAPHID
from hid.usb import USBHID
from ctap.constants import AUTHN_CMD
from ctap.keep_alive import CTAPHIDKeepAlive
from bridge.datatypes import AuthenticatorVersion, BridgeException

from smartcard.System import readers

logging.basicConfig()
log = logging.getLogger('bridge')
log.setLevel(logging.DEBUG)

class Bridge():

    VERSION = AuthenticatorVersion(2,1,0,0)
    KEEP_ALIVE_TIME_MS=15000

    def __init__(self):
        self._pcsc = None
        self._usbdevice = None
        self._usbhid = None
        self._ctaphid = None
     
    def shutdown(self):
        self._usbhid.shutdown()
        # self._pcsc.disconnect()

    def start(self, reader, device:str="/dev/ctaphid"):
        # self._pcsc = red.createConnection()
        # self._pcsc.connect()
        # self._pcsc.transmit([0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01])
        self._usbdevice = os.open(device, os.O_RDWR)
        self._usbhid = USBHID(self._usbdevice)
        self._ctaphid = CTAPHID(self._usbhid)
        self._ctaphid.set_authenticator(self)
        self._usbhid.set_listener(self._ctaphid)
        self._usbhid.start()

    def process_cbor(self, cbor_data:bytes, keep_alive: CTAPHIDKeepAlive, cid:bytes=None)->bytes:
        keep_alive.start(Bridge.KEEP_ALIVE_TIME_MS)
        cmd = cbor_data[:1]
        log.debug("Received %s CBOR: %s", AUTHN_CMD(cmd).name, cbor_data.hex())

        nfc_data = bytes([ 0x80, 0x10, 0x00, 0x00, len(cbor_data) ]) + cbor_data + bytes([ 0x00 ])
        log.debug("Sending NFC data: %s", nfc_data.hex())

        # self._pcsc.connection.transmit()

        keep_alive.stop()

    def process_wink(self, payload:bytes, keep_alive: CTAPHIDKeepAlive)->bytes:
        log.info("WINK ;)")

    def get_version(self)->AuthenticatorVersion:
        return Bridge.VERSION


bridge = Bridge()

def signal_handler(sig, frame):
    bridge.shutdown()
    mdir = Path(__file__).parent.resolve() / "scripts"
    os.system(mdir / "teardown_ctaphid.sh")
    sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = 'FIDO2 PC/SC CTAPHID Bridge')
    parser.add_argument('-l', '--list-readers', action='store_true', dest='listreaders',  help='list available PC/SC readers')
    parser.add_argument('-r', '--reader', nargs='?', dest='reader', type=int, 
        const=0, default=0, required=False, help='index of the PC/SC reader to use (default: 0)')
    args = parser.parse_args()

    redlist = readers()
    redlist.sort(key=str)

    if(len(redlist) == 0):
        log.warn('No PC/SC readers found')

    if(args.listreaders):
        if(len(redlist) != 0):
            log.info('Available PC/SC readers (' + str(len(redlist)) + '):')
            for i, reader in enumerate(redlist):
                log.info(str(i) + ': ' + str(reader))
        exit(0)

    if(len(redlist) == 0 or args.reader < 0 or args.reader >= len(redlist)):
        log.error('Specified reader index is out of range')
        exit(1)
    red = redlist[args.reader]
    log.info('Using reader ' + str(args.reader) + ': ' + str(red))

    mdir = Path(__file__).parent.resolve() / "scripts"

    os.system(mdir / "setup_ctaphid.sh")
    time.sleep(1)
    bridge.start(red)

    signal.signal(signal.SIGINT, signal_handler)
    log.info('Press Ctrl+C to stop')
    signal.pause()
