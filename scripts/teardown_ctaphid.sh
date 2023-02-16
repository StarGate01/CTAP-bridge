#!/usr/bin/env bash

CONF=/sys/kernel/config/usb_gadget/ctaphid

echo "" > $CONF/UDC
rm $CONF/configs/c.1/hid.usb0
rmdir $CONF/configs/c.1/strings/0x409
rmdir $CONF/configs/c.1
rmdir $CONF/functions/hid.usb0
rmdir $CONF/strings/0x409
rmdir $CONF