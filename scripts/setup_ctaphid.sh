#!/usr/bin/env bash

CONF=/sys/kernel/config/usb_gadget/ctaphid

mkdir -p $CONF
mkdir -p $CONF/configs/c.1
mkdir -p $CONF/functions/hid.usb0
echo 0 > $CONF/functions/hid.usb0/protocol
echo 0 > $CONF/functions/hid.usb0/subclass
echo 64 > $CONF/functions/hid.usb0/report_length
echo -ne "\x06\xd0\xf1\x09\x01\xa1\x01\x09\x20\x15\x00\x26\xff\x00\x75\x08\x95\x40\x81\x02\x09\x21\x15\x00\x26\xff\x00\x75\x08\x95\x40\x91\x02\xc0" > $CONF/functions/hid.usb0/report_desc
mkdir $CONF/strings/0x409
mkdir $CONF/configs/c.1/strings/0x409
echo "0x05df" > $CONF/idProduct
echo "0x16c0" > $CONF/idVendor
echo "6548556985" > $CONF/strings/0x409/serialnumber
echo "CHRZ.de" > $CONF/strings/0x409/manufacturer
echo "FIDO PC/SC CTAPHID Bridge" > $CONF/strings/0x409/product
echo "Configuration 1" > $CONF/configs/c.1/strings/0x409/configuration
echo 120 > $CONF/configs/c.1/MaxPower
ln -s $CONF/functions/hid.usb0 $CONF/configs/c.1
echo "dummy_udc.0" > $CONF/UDC
