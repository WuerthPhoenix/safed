#!/bin/sh
# chkconfig: 2345 99 33
# description: SAFED agent
# processname: safed
# config: /etc/safed/safed.conf
########################################################################
#
#   (c) 2001-2006 Intersect Alliance Pty Ltd
#
#   This script controls Wuerth Phoenix safed for UNIX
#
#   Version 1.1
#
#   Usage: ${ETC}/init.d/safed { start | stop | restart } 
#
########################################################################

export PATH=${PATH}:/usr/bin:/usr/sbin:/sbin 

# etc value for Linux and Solaris
ETC=/etc
uname | grep HP-UX > /dev/null
RESULT=$?
if [ $RESULT -eq 0 ]; then
	# etc value for HP-UX
	ETC="/sbin"
fi

uname | grep AIX > /dev/null
RESULT=$?
if [ $RESULT -eq 0 ]; then
        # etc value for IBM-AIX
        ETC="/etc/rc.d"
fi


case "$1" in
'start_msg')
        echo "Starting safed daemon"
        ;;

'stop_msg')
        echo "Stopping safed daemon"
        ;;

'start')
        PID=`cat /var/run/safed.pid 2>/dev/null`
        if [ ! -z "$PID" ] ;  then
		echo "safed already running. Please stop safed first."
		exit 1
	fi

	id | grep '^uid=0' > /dev/null
	if [ $? -ne 0 ]; then
		echo "Sorry, you need to be root to start safed."
		exit 1
	fi
	
	if [ -f /usr/bin/safed ] ; then
		echo "safed starting."
		uname | grep AIX > /dev/null
		if [ $? -eq 0 ]; then
		 	startsrc -a '-l' -s safed
		else
			/usr/bin/safed -d
			PID=`cat /var/run/safed.pid 2>/dev/null`
			echo "... safed started with pid: ${PID}"
		fi
	fi
        ;;
'stop')
	id | grep '^uid=0' > /dev/null
	if [ $? -ne 0 ]; then
		echo "Sorry, you need to be root to stop safed."
		exit 1
	fi

	uname | grep AIX > /dev/null
	if [ $? -eq 0 ]; then
		stopsrc -s safed
	else
        	PID=`cat /var/run/safed.pid 2>/dev/null`
       		if [ ! -z "$PID" ] ;  then
			kill -TERM ${PID}
		fi
	fi
        ;;
'restart')
        if [ -f ${ETC}/init.d/safed ] ; then
		${ETC}/init.d/safed stop
		RC=$?
		if [ $RC -gt 0 ]; then
			exit $RC
		fi

		sleep 1

		${ETC}/init.d/safed start
		RC=$?
		if [ $RC -gt 0 ]; then
			exit $RC
		fi
	fi
	;;
	
*)
        echo "Usage: $0 { start | stop | restart }"
        ;;
esac

exit 0
