#!/usr/bin/env bash

CONF=/sys/kernel/config/usb_gadget/ctap_ccid_emu

mkdir -p $CONF

# General metadata
echo "0x1209" > $CONF/idVendor
echo "0x000C" > $CONF/idProduct
mkdir -p $CONF/strings/0x409
echo "6548556985" > $CONF/strings/0x409/serialnumber
echo "CHRZ.de" > $CONF/strings/0x409/manufacturer
echo "FIDO_CCID_Emulator" > $CONF/strings/0x409/product

# Configuration 1 metadata
mkdir -p $CONF/configs/c.1
mkdir -p $CONF/configs/c.1/strings/0x409
echo "Configuration 1" > $CONF/configs/c.1/strings/0x409/configuration
echo 250 > $CONF/configs/c.1/MaxPower

# Function 1 - CTAP2 HID
mkdir -p $CONF/functions/hid.ctap0
echo 0 > $CONF/functions/hid.ctap0/protocol
echo 0 > $CONF/functions/hid.ctap0/subclass
echo 64 > $CONF/functions/hid.ctap0/report_length
echo -ne "\x06\xd0\xf1\x09\x01\xa1\x01\x09\x20\x15\x00\x26\xff\x00\x75\x08\x95\x40\x81\x02\x09\x21\x15\x00\x26\xff\x00\x75\x08\x95\x40\x91\x02\xc0" > $CONF/functions/hid.ctap0/report_desc
ln -s $CONF/functions/hid.ctap0 $CONF/configs/c.1

if [ "$1" = "composite" ]; then
    # Function 2 - CCID
    mkdir -p $CONF/functions/ccid.sc0
    echo 0x000404FA > $CONF/functions/ccid.sc0/features
    ln -s $CONF/functions/ccid.sc0 $CONF/configs/c.1
fi

# Execute
echo $(ls /sys/class/udc) > $CONF/UDC

# Wait for Udev
until [ -e /dev/ctaphid ]; do
    sleep 1
done
until [ "$1" != "composite" ] || [ -e /dev/ccidsc ]; do
    sleep 1
done
