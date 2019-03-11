#!/bin/sh

########################################################################
#    
#    (c) 2010 Wuerth Phoenix
# 
#   This script will automate the installation of safed for UNIX.
#   
#   Version 1.0
#    
#    Usage: ./uninstall.sh
#
########################################################################

########################################################################
#   Check that the user has an effective userid of 0 (root) 
########################################################################

root_check()
{
     id | grep -c uid=0 > /dev/null
     RETVAL=$?

	if [ $RETVAL -gt 0 ]
	then
           echo "You need to be root to run this script. Terminating script."
           exit 7
        else
           echo "Confirmed your are logged in as root"
	fi

}


root_check

# for Linux and Solaris, this is the parent directory of rcX.d
RCPARENTDIR=/etc
# for Linux and Solaris, this it the directory containing the service start/stop scripts
INITDDIR=/etc/init.d

# systemd
SYSTEMD_DIR=/etc/systemd/system/
SERVICE=safed.service

KSEQ=33
SSEQ=99

####################################################################
# if I am running on SUSE Linux, then the rcX.d parent directory is /etc/init.d
uname | grep Linux >/dev/null && grep SUSE /etc/issue > /dev/null
if [ $? -eq 0 ]; then
	RCPARENTDIR="/etc/init.d"
fi


# if I am running on HP-UX, then the rcX.d parent directory is /sbin
uname | grep HP-UX > /dev/null
if [ $? -eq 0 ]; then
	RCPARENTDIR="/sbin"
	INITDDIR="/sbin/init.d"
	KSEQ=333 
	SSEQ=999
fi

uname|grep AIX >/dev/null
if [ $? -eq 0 ]; then
	INITDDIR="/etc/rc.d/init.d"
fi

####################################################################

#systemd service
if [ -f ${SYSTEMD_DIR}/${SERVICE} ];then
    systemctl stop ${SERVICE}
    systemctl disable ${SERVICE}
    rm -f ${SYSTEMD_DIR}/${SERVICE}
else
    # stopping the service
    uname | grep AIX > /dev/null
    if [ $? -eq 0 ]; then
    	echo "stopping the service on IBM-AIX"
    	/usr/bin/stopsrc -s safed
    else
    	echo "stopping the service" 
    	${INITDDIR}/safed stop
    fi
    
    echo "Removing safed binary..."
    if [ -f /usr/bin/safed ]
    then
    	rm -f /usr/bin/safed 2>/dev/null
            echo "Done."
    fi
    
    echo "I will leave the configuration file (/etc/safed/safed.conf) - please remove it manually if you intend to permanently remove the agent ..."
    
    # Remove the runlevel scripts
    echo "... removing the runlevel scripts"
    uname | grep AIX > /dev/null
    if [ $? -eq 0 ]; then
    	/usr/sbin/rmitab safed
    	/usr/bin/rmssys -s safed
    else
    	#/usr/lib/lsb/remove_initd ${INITDDIR}/safed
    	insserv -r safed
    	# TODO: qui va gestito l'exit status ed eventualmente la procedura di disinstallazione
    fi
    
    echo "... removing the start|stop script"
    rm ${INITDDIR}/safed 2>/dev/null
fi

# remove the pid file
rm -f /var/run/safed.pid 2>/dev/null
# remove itself
rm -f /etc/safed/safed_uninstall.sh
