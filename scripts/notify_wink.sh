#!/usr/bin/env bash

USERS=$(users)
TITLE="CTAPHID WINK"
MESSAGE="Please tap your FIDO token to the reader."

for USER in $USERS
do
    CUID=$(id -u $USER)
    sudo -u $USER DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$CUID/bus notify-send "$TITLE" "$MESSAGE" -a "CTAP Bridge" -i dialog-information
done
