#!/bin/sh
mv libedsio.so.0 libxdelta.so.2 /usr/lib/
#mv liblog.so libckpt.so /usr/local/lib/
mv xdelta /usr/bin/
mv logger /usr/local/bin/

sudo /sbin/chkconfig crond on
sudo /etc/init.d/crond start
# sudo rm /usr/local/lib/
# "echo \"tag: %(host)\" >> geels/i3d.conf"
