#!/bin/bash
# Test concurrency of message variables
# Added 2015-11-03 by rgerhards
# This file is part of the rsyslog project, released  under ASL 2.0
echo ===============================================================================
echo \[msgvar-functionfield-nomatch.sh\]: testing concurrency of local variables
. $srcdir/diag.sh init
. $srcdir/diag.sh startup msgvar-functionfield-nomatch.conf
sleep 1
. $srcdir/diag.sh shutdown-when-empty # shut down rsyslogd when done processing messages
. $srcdir/diag.sh wait-shutdown
. $srcdir/diag.sh exit
