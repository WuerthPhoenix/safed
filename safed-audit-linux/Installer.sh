#!/bin/bash
#
# Makefile installation helper

if [ -z "$1" ]; then ACTION="-i";else ACTION=$1;fi
if [ -z "$2" ]; then CONFDIR="/etc";else CONFDIR=$2;fi
if [ -z "$3" ]; then BINDIR="/usr/sbin";else BINDIR=$3;fi
if [ -z "$4" ]; then SAFEDPIPE="/tmp/safedpipe";else SAFEDPIPE=$4;fi


#Find out where auditd.conf resides
if [ -f $CONFDIR/audit/auditd.conf ]; then
	AUDITCONF="audit/auditd.conf"
	AUDITRULES="audit/audit.rules"
else
	AUDITCONF="auditd.conf"
	AUDITRULES="audit.rules"
fi

if [ "$ACTION" == "-i" ]; then
	# Install
	VERSION=`/sbin/auditctl -v | /usr/bin/awk '{print $3}'`
	MAJOR=`echo $VERSION | cut -d. -f1`
	MINOR=`echo $VERSION | cut -d. -f2`
	RELEASE=`echo $VERSION | cut -d. -f3`

	VERSIONOK=0
	if [ $MAJOR -gt 1 ]; then
		VERSIONOK=1
	elif [ $MAJOR -eq 1 ]; then
		if [ $MINOR -gt 0 ]; then
			VERSIONOK=1
		elif [ $MINOR -eq 0 ]; then
			if [ $RELEASE -ge 15 ]; then
				VERSIONOK=1
			fi
		fi
	fi

	if [ $VERSIONOK -ne 1 ]; then
		echo "Version 1.0.15 of the native audit daemon is required in order"
		echo "for safed to operate correctly. Please install this version"
		echo "or later."
		exit
	fi

	ps -ef | grep safed > /dev/null
    if [ $? -ne 0 ]
	then
	    echo "Start safed agent first!"
		exit
	fi

	if [ ! -p $SAFEDPIPE ]; then
		echo "Named FIFO $SAFEDPIPE is required. Please check it."
		exit	
	fi	

	$CONFDIR/init.d/auditd stop

	if [ ! -f $CONFDIR/$AUDITCONF-safedbackup ]; then
        	cp $CONFDIR/$AUDITCONF $CONFDIR/$AUDITCONF-safedbackup
	fi
	if [ ! -f $CONFDIR/$AUDITRULES-safedbackup ]; then
        	cp $CONFDIR/$AUDITRULES $CONFDIR/$AUDITRULES-safedbackup
	fi
 
	if [ -f /usr/sbin/semodule ] && [ -f safed.pp ]; then
		/usr/sbin/semodule -i safed.pp
	fi

	echo "# SafedDispatchHelper added" > $CONFDIR/$AUDITCONF
	cat $CONFDIR/$AUDITCONF-safedbackup | sed 's/^dispatcher.*//' | sed 's/^log_format =.*/log_format = NOLOG/' | egrep -v "^$" >> $CONFDIR/$AUDITCONF

	echo "dispatcher = $BINDIR/SafedDispatchHelper" >> $CONFDIR/$AUDITCONF
	cat $CONFDIR/$AUDITRULES-safedbackup | sed 's/^-D.*//' | egrep -v "^$" > $CONFDIR/$AUDITRULES

	$CONFDIR/init.d/auditd start
	exit
fi

if [ "$1" == "-u" ]; then
	# Uninstall
	UNINST=`rpm -q SafedLinux | wc -l`
	if [ $UNINST -le 1 ]; then
		$CONFDIR/init.d/auditd stop
		if [ -f $CONFDIR/$AUDITCONF-safedbackup ]; then
			cat $CONFDIR/$AUDITCONF-safedbackup | sed 's/^log_format =.*/log_format = RAW/' | egrep -v "^dispatcher = .*SafedDispatch.*" > $CONFDIR/$AUDITCONF
			rm -f $CONFDIR/$AUDITCONF-safedbackup
		else
			cp $CONFDIR/$AUDITCONF $CONFDIR/$AUDITCONF-safedbackup
			cat $CONFDIR/$AUDITCONF-safedbackup | sed 's/^log_format =.*/log_format = RAW/' | egrep -v "^dispatcher" > $CONFDIR/$AUDITCONF
			rm -f $CONFDIR/$AUDITCONF-safedbackup
		fi

		if [ -f /usr/sbin/semodule ]; then
			/usr/sbin/semodule -l | egrep "^safed" > /dev/null
			if [ "$?" -eq 0 ]; then
				/usr/sbin/semodule -r safed;
			fi
		fi

		$CONFDIR/init.d/auditd start
	fi
	exit
fi
