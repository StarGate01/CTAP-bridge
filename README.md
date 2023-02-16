# FIDO2 PC/SC CTAPHID Bridge

This project provides a translation bridge for NFCCTAP authenticators connected via PC/SC to a virtual USB device using CTAPHID. This enables software which only implements support for USB CTAPHID to use NFC FIDO2 tokens via PC/SC as well.

This project has been forked from the *Virtual WebAuthn Authenticator* project at https://github.com/UoS-SCCS/VirtualWebAuthn , which provides a fully virtualized authenticator. This implementation has been removed and replaced by the bridging code, only the HID and CTAP drivers are still used. For more information and documentation on CTAP2, see that repository, this fork has been stripped down to the bare minimum.

## Setup

Linux is required, or any other POSIX system which supports configFS and USB gadgets.

### Kernel

Ensure that the modules `dummy_hcd` and `libcomposite` are loaded. The directory `/sys/kernel/config/usb_gadget` should be available.

The Linux kernel has to built with these configuration option to enable USB gadget, the USB host emulator, and config FS support. This is usually the case if you use a standard kernel.

```
USB y
USB_GADGET y
USB_CONFIGFS y
USB_CONFIGFS_F_FS y
```

### USB config

The scripts in `scripts/` use config FS to setup the USB Gadget. 

The USB ID `16c0:05df` belongs to the authors of the original VirtualWebAuthn repository, it is recommended to change it. Make sure to then adjust the udev rules as well.

You can lso change the manufacturer name, product name, and serial number if you want to.
### Udev config

Udev has to be configures to allow access to the emulated USB device as well. This will also setup a symlink `/dev/ctaphid` to the emulated USB device, which is used by the scripts.

```
KERNEL=="hidg[0-9]", SUBSYSTEM=="hidg", SYMLINK+="ctaphid", MODE+="0666", TAG+="uaccess"
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="16c0", ATTRS{idProduct}=="05df", MODE+="0666", TAG+="uaccess"
```

If your distribution uses `plugdev`, add `,  GROUP="plugdev"` to both lines.