#!/bin/bash
# This is part of the rsyslog testbench, licensed under ASL 2.0
. ${srcdir:=.}/diag.sh init
generate_conf
add_conf '
# provides kernel logging support and enable non-kernel klog messages
module(load="../plugins/imklog/.libs/imklog" permitnonkernelfacility="on")

module(load="../plugins/imuxsock/.libs/imuxsock" sysSock.use="off")
input(type="imuxsock" Socket="'$RSYSLOG_DYNNAME'-testbench_socket")

template(name="RSYSLOG_StdJSONFmt" type="string" 
	string="{\"message\":\"%msg:::json%\",\"fromhost\":\"%HOSTNAME:::json%\",\"facility\":\"%syslogfacility-text%\",\"priority\":\"%syslogpriority-text%\",
		\"timereported\":\"%timereported:::date-rfc3339%\",
		\"timegenerated\":\"%timegenerated:::date-rfc3339%\"}\n\n")
# :msg, contains, "msgnum:" {
	action(type="omfile" template="RSYSLOG_FileFormat"	file=`echo $RSYSLOG_OUT_LOG`)
	action(type="omfile" template="RSYSLOG_StdJSONFmt"	file=`echo $RSYSLOG_OUT_LOG`)
#	action(type="omfile" template="RSYSLOG_DebugFormat"	file=`echo $RSYSLOG_OUT_LOG`)
# }
'
startup
logger -d -u $RSYSLOG_DYNNAME-testbench_socket msgnum:1
# injectmsg  0 1

shutdown_when_empty # shut down rsyslogd when done processing messages
wait_shutdown    # we need to wait until rsyslogd is finished!

printf '{"backslash":"a \\\\ \\"b\\" c / d"}\n' | cmp - $RSYSLOG_OUT_LOG
if [ ! $? -eq 0 ]; then
  echo "invalid JSON generated, $RSYSLOG_OUT_LOG is:"
  cat $RSYSLOG_OUT_LOG
  error_exit 1
fi;

exit_test
