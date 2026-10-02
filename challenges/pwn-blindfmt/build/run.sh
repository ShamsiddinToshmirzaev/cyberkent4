#!/bin/sh
cd /tmp
exec setpriv --reuid=1000 --regid=1000 --clear-groups /chal/ld-linux-x86-64.so.2 --library-path /chal /chal/vuln
