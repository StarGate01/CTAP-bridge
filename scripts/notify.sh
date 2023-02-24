#!/usr/bin/env bash

echo "Sending message: $1"

USERS=$(users)

for USER in $USERS; do
    CUID=$(id -u $USER)
    sudo -u $USER DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$CUID/bus notify-send "FIDO NFC Token" "$1" -c "$2" -a "CTAP Bridge" -i dialog-information -e
done
