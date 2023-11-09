#!/usr/bin/env bash

CONF=/sys/kernel/config/usb_gadget/ctap_ccid_emu

[[ -f $CONF/UDC ]] && echo "" > $CONF/UDC

rm -f $CONF/configs/c.1/hid.ctap0
rm -f $CONF/configs/c.1/ccid.sc0

rmdir $CONF/configs/c.1/strings/0x409 2>/dev/null
rmdir $CONF/configs/c.1 2>/dev/null

rmdir $CONF/functions/hid.ctap0 2>/dev/null
rmdir $CONF/functions/ctap.sc0 2>/dev/null

rmdir $CONF/strings/0x409 2>/dev/null
rmdir $CONF 2>/dev/null