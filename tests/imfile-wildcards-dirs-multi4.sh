#!/bin/bash
# This is part of the rsyslog testbench, licensed under GPLv3
export IMFILEINPUTFILES="1"
export IMFILEINPUTFILESSTEPS="5"
export IMFILEINPUTFILESALL=$(($IMFILEINPUTFILES * $IMFILEINPUTFILESSTEPS))
echo [imfile-wildcards-multi4.sh]
. $srcdir/diag.sh check-inotify-only
. $srcdir/diag.sh init
# generate input files first. Note that rsyslog processes it as
# soon as it start up (so the file should exist at that point).

# Start rsyslog now before adding more files
. $srcdir/diag.sh startup imfile-wildcards-dirs-multi4.conf
# sleep a little to give rsyslog a chance to begin processing
sleep 1

for i in `seq 1 $IMFILEINPUTFILES`;
do
	echo "Make rsyslog.input.dir$i"
	mkdir rsyslog.input.dir$i
	./msleep 100
done

for j in `seq 1 $IMFILEINPUTFILESSTEPS`;
do
	echo "Loop Num $j"
	for i in `seq 1 $IMFILEINPUTFILES`;
	do
		echo "Make rsyslog.input.dir$i/dir$j/testdir"
		mkdir rsyslog.input.dir$i/dir$j
		./msleep 25
		mkdir rsyslog.input.dir$i/dir$j/testdir
		./msleep 25
		mkdir rsyslog.input.dir$i/dir$j/testdir/su$j
		./msleep 25
		mkdir rsyslog.input.dir$i/dir$j/testdir/su$j/bd$j
		./msleep 25
		mkdir rsyslog.input.dir$i/dir$j/testdir/su$j/bd$j/ir$j
		./msleep 25
		./inputfilegen -m 1 > rsyslog.input.dir$i/dir$j/testdir/su$j/bd$j/ir$j/file.logfile
		./msleep 50
	done
	ls -d rsyslog.input.*

	# Delete all but first!
	for i in `seq 1 $IMFILEINPUTFILES`;
	do
		rm -rf rsyslog.input.dir$i/dir$j/testdir/su$j/bd$j/ir$j/file.logfile
		./msleep 50
		rm -rf rsyslog.input.dir$i/dir$j
	done
done

# sleep a little to give rsyslog a chance for processing
sleep 1

. $srcdir/diag.sh shutdown-when-empty # shut down rsyslogd when done processing messages
. $srcdir/diag.sh wait-shutdown	# we need to wait until rsyslogd is finished!
. $srcdir/diag.sh content-check-with-count "HEADER msgnum:00000000:" $IMFILEINPUTFILESALL
. $srcdir/diag.sh exit
