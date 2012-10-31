#!/bin/sh
########################################################################
# SAFED for AIX
# Author: Wuerth-Phoenix s.r.l.,
# made starting from:
#    (c) 2001-2010 Intersect Alliance Pty Ltd
# 
#   This script will automate the installation of the safed audit daemon.
#   
#   Version 1.8
#    
#    Usage: ./install.sh
#
########################################################################





########################################################################
#   Check that the necessary files are contained within the local
#   directory. 
########################################################################

file_check()
{

     if [ ! -f src/safedcore ];then
        echo "The safedcore binary file is missing. Terminating script."
        exit 1
     fi

     if [ ! -f src/safedjoin ];then
        echo "The safedjoin binary file is missing. Terminating script."
        exit 1
     fi

     if [ ! -f install/restartsafed ];then
        echo "The audit restart script is missing. Terminating script."
        exit 1 
     fi

     if [ ! -f install/safedstream ];then
        echo "The safed stream script is missing. Terminating script."
        exit 1 
     fi

     if [ ! -f /etc/safed/safed.conf ];then
        echo "The safed config file /etc/safed/safed.conf is missing. Terminating script."
        exit 1 
     fi

     if [ ! -f uninstall.sh ]
     then
        echo "The safed removal script is missing. Terminating script."
        exit 1 
     fi
}

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
           exit 1
        else
           echo "Confirmed that you are logged in as root"
	fi

}

########################################################################
#   Check that the software patch level is OK.
########################################################################

check_os_and_patch_level()
{
   uname -a | egrep "AIX" > /dev/null
   RETVAL=$?

   if [ $RETVAL -gt 0 ]
   then
     echo "This application is designed for AIX systems only. Terminating script"
     exit 1
   fi 
}

########################################################################
#   Check that the AIX audit sub-system is installed.
########################################################################

check_audit_is_on()
{
    # Seems to be on by default. Continue for the moment.
    echo
}


########################################################################
#   This routine will back up the key audit related files
########################################################################

backup_key_files()
{
   echo "Backing up key files..........."

   if [ ! -f /etc/security/audit/config.safed-backup ];then
      cp /etc/security/audit/config /etc/security/audit/config.safed-backup
      RETVAL=$?
      if [ $RETVAL -gt 0 ]
      then
        echo "Unable to backup the /etc/security/audit/config file. Terminating script"
        exit 1
      fi
   else
      echo "Backup of the audit config file already exists. Not overwriting"
   fi
}

check_binary()
{
	echo "Verifying that the binaries will work on this system..."
	src/bintest
	if [ $? -ne 1 ]; then
		recompile
	else
		echo "The included binaries seem to work on this system."
	fi
}

recompile()
{
	echo "The included binaries do not work on your architecture."
}

########################################################################
#  This is the main loop  
########################################################################

check_audit_is_on
file_check 
root_check
check_os_and_patch_level
backup_key_files
check_binary




if [ -f /etc/security/audit/safedstream ]; then
	echo "WARNING: It looks as though Safed audit is already installed."
	echo
	echo "Please uninstall Safed audit first before proceeding, using the safed_uninstall.sh script in /etc/security/audit/"
	echo
	exit
fi

# Kill off any outstanding pid files.
if [ -f /var/run/safedcore.pid ]; then
	rm -f /var/run/safedcore.pid >/dev/null 2>&1
fi

 
#check if safed agent is running
ps -ef | grep safed > /dev/null
if [ $? -ne 0 ];then
   echo "Start safed agent first!"
   exit 1
fi


########################################################################
#  This provides the final warning before the software is loaded onto
#  the system. In case of mistakes, it allows the user to escape before 
#  the software is loaded.   
########################################################################

echo 
echo "*************************************************"
echo 
echo "You are about to install Safed audit on this host."




########################################################################
#  This will copy the common workstation and server files to
#  to /etc directory.  
########################################################################


# Kill the audit daemon, if it is alive
/usr/sbin/audit shutdown >/dev/null 2>&1
sleep 2

echo
echo "Installing common files..........."

if [ ! -p /tmp/safedpipe ]; then
   mkfifo /tmp/safedpipe
fi
#check if the pipe tmp/safedpipe exists
if [ ! -p /tmp/safedpipe ]; then
	echo "Named FIFO /tmp/safedpipe is required. Please check it."
	exit 1	
fi	

cp src/safedcore src/safedjoin /usr/bin/

RETVAL=$?
if [ $RETVAL -gt 0 ];then
  echo "Unable to copy the safedcore and safedjoin programs to /usr/bin. Terminating script"
  exit 1
fi

chown root:system /usr/bin/safedcore /usr/bin/safedjoin
RETVAL=$?
if [ $RETVAL -gt 0 ];then
  echo "Unable to change owner for file to /usr/bin/safedcore and /usr/bin/safedjoin. Terminating script"
  exit 1
fi
chmod  550 /usr/bin/safedcore /usr/bin/safedjoin
RETVAL=$?
if [ $RETVAL -gt 0 ];then
  echo "Unable to change the permissions for file to /usr/bin/safedcore and /usr/bin/safedjoin. Terminating script"
  exit 1
fi

cp install/restartsafed install/safedconfig.template install/safedstream /etc/security/audit/
RETVAL=$?
if [ $RETVAL -gt 0 ];then
  echo "Unable to copy support files into /etc/security/audit. Terminating script"
  exit 1
fi

chown root:system /etc/security/audit/restartsafed /etc/security/audit/safedconfig.template /etc/security/audit/safedstream
RETVAL=$?
if [ $RETVAL -gt 0 ];then
  echo "Unable to change owner for the support files in /etc/security/audit. Terminating script"
  exit 1
fi

chmod  550 /etc/security/audit/restartsafed /etc/security/audit/safedstream
RETVAL=$?
if [ $RETVAL -gt 0 ];then
  echo "Unable to change the permissions for the support files in /etc/security/audit. Terminating script"
  exit 1
fi


cp uninstall.sh /etc/security/audit/safed_uninstall.sh
RETVAL=$?
if [ $RETVAL -gt 0 ];then
  echo "Unable to copy the safed uninstall.sh script to /etc/security/audit. Terminating script"
  exit 1
fi

echo
echo "Successfully installed the common files"
echo




echo
echo "Successfully installed the necessary files. Activating auditing..."
echo 

/etc/security/audit/restartsafed

sleep 2

PID=`/usr/bin/ps -e -u 0|/usr/bin/fgrep safedcore|/usr/bin/egrep -v fgrep|/usr/bin/awk '{print $1}'`
if [ -z "$PID" ] ;  then
        echo "Snare audit not running. Please check installation parameters."
        exit 1;
fi

echo "Done."
echo
echo "Safed audit will also be activated after a reboot via the"
echo "normal AIX audit init process."
echo
echo "Please connect to the local machine using your web browser"
echo "using the following URL: http://"`hostname`":6161/"
echo ""

exit 0

