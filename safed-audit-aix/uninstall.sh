#!/bin/sh

########################################################################
# SAFED for AIX
# Author: Wuerth-Phoenix s.r.l.,
#    (c) 2001-2010 Intersect Alliance Pty Ltd
# 
#   This script will automate the installation of the safed audit daemon.
#   
#   Version 1.1
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

	if [ $RETVAL -gt 0 ];then
           echo "You need to be root to run this script. Terminating script."
           exit 7
        else
           echo "Confirmed your are logged in as root"
	fi

}

########################################################################
#   This routine will restore the key audit related files in
#   /etc/security/audit
########################################################################

restore_key_files()
{
   echo "Restoring key files..........."

   echo "Restoring oringinal /etc/security/audit/config..."
   if [ -f /etc/security/audit/config.safed-backup ];then
      cp /etc/security/audit/config.safed-backup /etc/security/audit/config
      RETVAL=$?
      if [ $RETVAL -gt 0 ];then
        echo "Unable to restore /etc/security/audit/config to its original value."
      fi
   else
	echo "Cannot find /etc/security/audit/config.safed-backup. Cannot restore."
   fi 

   echo "Removing safedcore binary..."
   if [ -f /usr/bin/safedcore ];then
	rm /usr/bin/safedcore 2>/dev/null
        echo "Done."
   fi

   if [ -f /usr/bin/safedjoin ];then
        echo "Removing safedjoin binary..."
        rm /usr/bin/safedjoin 2>/dev/null
        echo "Done."
   fi

   if [ -f /etc/security/audit/restartsafed ];then
        echo "Removing safed restart script..."
        rm /etc/security/audit/restartsafed 2>/dev/null
        echo "Done."
   fi

   if [ -f /etc/security/audit/safedstream ];then
        echo "Removing safed stream script..."
        rm /etc/security/audit/safedstream 2>/dev/null
        echo "Done."
   fi

   if [ -f /etc/security/audit/safedconfig.template ];then
        echo "Removing safed configuration template..."
        rm /etc/security/audit/safedconfig.template 2>/dev/null
        echo "Done."
   fi


   echo "Removing safed backup files."
   rm -f /etc/security/audit/*.safed-backup
   echo "Done."

}

/usr/sbin/audit shutdown

root_check
restore_key_files

#if [ -p $(safedpipe) ]; then 
#   rm -f $(safedpipe)
#fi
rm -f /var/run/safedcore.pid 2>/dev/null
rm -f /etc/security/audit/safed_uninstall.sh

