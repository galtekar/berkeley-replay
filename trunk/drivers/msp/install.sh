#!/bin/sh

# Install udev rules so that non-root users can access the device.
# Otherwise, the default permission of 600 will be used, which means you
# can use it only as root.
cp 99-msp.rules /etc/udev/rules.d/
