#!/usr/bin/env bash

CONF=/sys/kernel/config/usb_gadget/ctaphid

[[ -f $CONF/UDC ]] && echo "" > $CONF/UDC
rm -f $CONF/configs/c.1/hid.usb0
rmdir $CONF/configs/c.1/strings/0x409 2>/dev/null
rmdir $CONF/configs/c.1 2>/dev/null
rmdir $CONF/functions/hid.usb0 2>/dev/null
rmdir $CONF/strings/0x409 2>/dev/null
rmdir $CONF 2>/dev/null