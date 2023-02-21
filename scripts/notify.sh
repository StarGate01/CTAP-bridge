#!/usr/bin/env bash

USERS=$(users)

for USER in $USERS; do
    CUID=$(id -u $USER)
    sudo -u $USER DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$CUID/bus notify-send "$1" "$2" -c "$3" -a "CTAP Bridge" -i dialog-information -e
done
