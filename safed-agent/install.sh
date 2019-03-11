#!/bin/sh
########################################################################
#    
#    (c) 2009, 2010 Wuerth Phoenix srl
# 
#   This script will automate the installation of safed for UNIX.
#   It performs the following operations:
#   - it copies the agent binary into the directory /usr/bin
#   - it copies the agent start|stop script into the directory /etc/init.d or /sbin/init.d depending on the OS
#   - if necessary, it creates the configuration directory, and copies in it a basic configuration file
#   - it creates the simbolic link prepended with S or K to the start|stop script in the /etc/rcX.d directories
#     (on HP-UX in the /sbin/rcX.d directories)
#
#   Version 1.0
#    
#    Usage: ./install.sh
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
           exit 1
        else
           echo "Confirmed that you are logged in as root"
	fi

}

########################################################################
#  Check the OS
########################################################################

check_os()
{
   uname | egrep "(Linux|SunOS|HP-UX|AIX)" > /dev/null
   RETVAL=$?

   if [ $RETVAL -gt 0 ]
   then
     echo "This agent is currently designed for Linux, Solaris, HP-UX and AIX operating systems only. Terminating script"
     exit 1
   fi 
	
}


########################################################################
#  This is the main loop  
########################################################################

# check that all the necessary files are contained into the installation directory
#file_check 
root_check
check_os

INSTAL=0
SNAREC=0
EPILOG_CONF=0

AGENT_NAME=safed
AGENT_BINARY=safed
SERVICE_SCRIPT=safed
SRC_CONF_FILE=safed.conf.basic

# for Linux and Solaris, this is the parent directory of rcX.d
RCPARENTDIR=/etc
# for Linux and Solaris, this it the directory containing the service start/stop scripts
INITDDIR=/etc/init.d

CONFDIR=/etc/safed
CONF_FILE=safed.conf
PID_FILE=/var/run/safed.pid
LOG_DIR=/var/log/safed

# systemd 
SYSTEMD_DIR=/etc/systemd/system/
SERVICE=safed.service

########################################################################################
# if I am running on SUSE Linux, then the rcX.d parent directory is /etc/init.d
uname | grep Linux >/dev/null && grep SUSE /etc/issue > /dev/null
if [ $? -eq 0 ]; then
	RCPARENTDIR="/etc/init.d"
fi


uname | grep HP-UX > /dev/null
if [ $? -eq 0 ]; then
	# if I am running on HP-UX, then the rcX.d parent directory is /sbin
	RCPARENTDIR="/sbin"
	INITDDIR="/sbin/init.d"
fi

uname|grep AIX >/dev/null
if [ $? -eq 0 ]; then
	INITDDIR="/etc/rc.d/init.d"
fi
#########################################################################################

#############################################################################
# Checking if this is a fresh installation or an upgrade of a preexisting one
#############################################################################

if [ -f ${CONFDIR}/${CONF_FILE} ]; then
   echo "... detected a preexisting SAFED configuration"
   SNAREC=1
fi

if [ -f /etc/snare/epilog/epilog.conf ]; then
   echo "... detected a preexisting Snare Epilog configuration"
   EPILOG_CONF=1
fi

# verifica che ${INITDDIR}/${SERVICE_SCRIPT} esista

if [ -f ${INITDDIR}/${SERVICE_SCRIPT} -o -f ${SYSTEMD_DIR}/${SERVICE} ]; then
	echo "WARNING: It looks as though ${AGENT_NAME} is already installed."
	echo
	echo "Please uninstall ${AGENT_NAME} first before proceeding: /etc/safed/safed_uninstall.sh"
	echo
	exit
fi

# Kill off any outstanding pid files.
if [ -f ${PID_FILE} ]; then
	rm -f ${PID_FILE} >/dev/null 2>&1
fi
###########################################################################

if [ "$SNAREC" -eq "1" -o "$EPILOG_CONF" -eq "1" ]; then
	while [ "$INSTAL" -ne "1" ] && [ "$INSTAL" -ne "2" ]
	do
	  echo 
	  echo "Enter [1] to install a basic starting configuration"
	  echo "Enter [2] to preserve the EXISTING configuration file"
	  echo "Enter anything else to terminate the script"
	  echo -n "Selection: "
	    read INSTAL
	    case $INSTAL in
	       1) echo "Installing basic configuration files"; INSTALL_TYPE=1 ;;
	       2) echo "Preserving existing Safed configuration"; INSTALL_TYPE=2;;
	       *) echo "Script terminating at user request"; exit 1 ;;
	    esac 
	done
else
   INSTALL_TYPE=1
fi
 

########################################################################
#  This provides the final warning before the software is installed onto
#  the system. In case of mistakes, it allows the user to escape before 
#  the software is installed.   
########################################################################

echo 
echo "*************************************************"
echo 
echo "You are about to install ${AGENT_NAME} on this host."
echo "Your selections are as follows:"
if [ $INSTALL_TYPE -eq 1 ]; then
  echo "Basic Installation"
else
  echo "Preserving existing configuration file."
fi



########################################################################
#  This will copy the common files to the /etc directory.  
########################################################################

if [ $INSTALL_TYPE -eq 1 ] || [ $INSTALL_TYPE -eq 2 ]; then
   echo
   echo "... checking and creating the directory for the agent configuration"
   mkdir -p ${CONFDIR}
   
   echo
   echo "... checking and creating the directory for the agent cache"
   mkdir -p ${LOG_DIR}

   echo "... installing the binary"
   cp ./${AGENT_BINARY} /usr/bin/${AGENT_BINARY}
   
   RETVAL=$?
   if [ $RETVAL -gt 0 ]
   then
     echo "Unable to copy ${AGENT_BINARY} program to /usr/bin. Terminating script"
     exit 1
   fi

   echo "... setting the binary permission"
   chown root /usr/bin/${AGENT_BINARY}
   RETVAL=$?
   if [ $RETVAL -gt 0 ]
   then
     echo "Unable to change owner for file to /usr/bin/${AGENT_BINARY}. Terminating script"
     exit 1
   fi
   chmod  550 /usr/bin/${AGENT_BINARY}
   RETVAL=$?
   if [ $RETVAL -gt 0 ]
   then
     echo "Unable to change the permissions for file to /usr/bin/${AGENT_BINARY}. Terminating script"
     exit 1
   fi

   cp uninstall.sh /etc/safed/safed_uninstall.sh
   RETVAL=$?
   if [ $RETVAL -gt 0 ]
   then
     echo "Unable to copy the safed uninstall.sh script to /etc/safed. Terminating script"
     exit 1
   fi

   RETVAL=0
   if [ $SNAREC -eq 0 ]; then
     # this means that there is not a preexisting safed installation
     if [ $EPILOG_CONF -eq 1 ]; then
	echo "... moving the existing epilog configuration to safed configuration"
        mv /etc/snare/epilog/epilog.conf ${CONFDIR}/${CONF_FILE}
	RETVAL=$?
     fi
   fi
   
   if [ $RETVAL -gt 0 ]
   then
     echo "Unable to move the epilog configuration file to ${CONFDIR}/${CONF_FILE}. Terminating script"
     exit 1
   fi

   #systemd service
   if [ -d ${SYSTEMD_DIR} ];then
       cp ./safed.service.template ${SYSTEMD_DIR}/${SERVICE}
       RETVAL=$?
       if [ $RETVAL -gt 0 ]
          then
          echo "Unable to copy the service to: ${SYSTEMD_DIR}/${SERVICE}. Terminating script"
          exit 1
       fi
       systemctl enable ${SERVICE}
   else
       ######################################
       #  Creating the start|stop scripts   #
       ######################################
       
       # this is only for IBM AIX
       uname|grep AIX >/dev/null
       if [ $? -eq 0 ]; then
            echo "... configuring the System Resource Controller for IBM-AIX"
            /usr/bin/mkssys -s safed -p /usr/bin/safed -u 0 -S -f 9 -n 15
            RETVAL=$?
            if [ $RETVAL -gt 0 ]
            then
                    echo "Unable to create the SRC entry for safed. Terminating script"
                    exit 1
            fi
       fi
       
       # this is for all the platforms
       echo "... installing the service start|stop script"
       cp ./safed_start.sh  ${INITDDIR}/${SERVICE_SCRIPT}
       RETVAL=$?
       if [ $RETVAL -gt 0 ]
          then
          echo "Unable to copy the startup script: ${INITDDIR}/${SERVICE_SCRIPT}. Terminating script"
          exit 1
       fi
       

       ############################################################################
       #   Configuring the automatic start|stop of the service at boot/shutdown   #
       ############################################################################
       echo "... configuring the service at the right runlevels"
       uname | grep Linux > /dev/null
       RETVAL=$?
       if [ $RETVAL -eq 0 ]; then
               echo "... on a Linux system the service isstarted on runlevels 2, 3, 4, 5"
               ln -s ${INITDDIR}/${SERVICE_SCRIPT} ${RCPARENTDIR}/rc0.d/K33${SERVICE_SCRIPT}
               ln -s ${INITDDIR}/${SERVICE_SCRIPT} ${RCPARENTDIR}/rc1.d/K33${SERVICE_SCRIPT}
               ln -s ${INITDDIR}/${SERVICE_SCRIPT} ${RCPARENTDIR}/rc2.d/S99${SERVICE_SCRIPT}
               ln -s ${INITDDIR}/${SERVICE_SCRIPT} ${RCPARENTDIR}/rc3.d/S99${SERVICE_SCRIPT}
               ln -s ${INITDDIR}/${SERVICE_SCRIPT} ${RCPARENTDIR}/rc4.d/S99${SERVICE_SCRIPT}
               ln -s ${INITDDIR}/${SERVICE_SCRIPT} ${RCPARENTDIR}/rc5.d/S99${SERVICE_SCRIPT}
               ln -s ${INITDDIR}/${SERVICE_SCRIPT} ${RCPARENTDIR}/rc6.d/K33${SERVICE_SCRIPT}
       else
               uname | grep SunOS > /dev/null
               RETVAL=$?
               if [ $RETVAL -eq 0 ]; then
                       echo "... on a Solaris system the service is started on runlevel 2"
                       ln ${INITDDIR}/${SERVICE_SCRIPT} ${RCPARENTDIR}/rc0.d/K33${SERVICE_SCRIPT}
                       ln ${INITDDIR}/${SERVICE_SCRIPT} ${RCPARENTDIR}/rc1.d/K33${SERVICE_SCRIPT}
                       ln ${INITDDIR}/${SERVICE_SCRIPT} ${RCPARENTDIR}/rc2.d/S99${SERVICE_SCRIPT}
               else
                       uname | grep AIX > /dev/null
                       RETVAL=$?
                       if [ $RETVAL -eq 0 ]; then
                              echo ".... on an IBM-AIX system the service is started on runlevel 2"
                              /usr/sbin/mkitab "safed:2:once:/usr/bin/startsrc -a '-l' -s safed > /dev/console 2>&1"
                       else
                              echo "... on a HP-UX system the service is started on runlevels 2, 3, 4"
                              ln -s ${INITDDIR}/${SERVICE_SCRIPT} ${RCPARENTDIR}/rc0.d/K333${SERVICE_SCRIPT}
                              ln -s ${INITDDIR}/${SERVICE_SCRIPT} ${RCPARENTDIR}/rc1.d/K333${SERVICE_SCRIPT}
                              ln -s ${INITDDIR}/${SERVICE_SCRIPT} ${RCPARENTDIR}/rc2.d/S999${SERVICE_SCRIPT}
                              ln -s ${INITDDIR}/${SERVICE_SCRIPT} ${RCPARENTDIR}/rc3.d/S999${SERVICE_SCRIPT}
                              ln -s ${INITDDIR}/${SERVICE_SCRIPT} ${RCPARENTDIR}/rc4.d/S999${SERVICE_SCRIPT}
                       fi
               fi
       fi

       RETVAL=$?
       if [ $RETVAL -gt 0 ]
       then
         echo "Unable to create ${RCPARENTDIR}/rc*.d files. Terminating script"
         exit 1
       fi
   fi
fi
	
########################################################################
#  This will copy the basic files to ${CONFDIR}
#  It will also change the owner and permissions for these files.
########################################################################

if [ $INSTALL_TYPE -eq 1 ]
then
   echo
   echo "... installing the basic configuration files"
   cp ./${SRC_CONF_FILE} ${CONFDIR}/${CONF_FILE}
   RETVAL=$?
   if [ $RETVAL -gt 0 ]
   then
     echo "Unable to copy the configuration file to ${CONFDIR}. Terminating script"
     exit 1 
   fi
   echo "... setting the right permission on the configuration files"
   chown root:root ${CONFDIR}/${CONF_FILE}
   chmod 600 ${CONFDIR}/${CONF_FILE}

fi

echo
echo "... installation successful. Starting the service ..."
echo 

if [ -d ${SYSTEMD_DIR} ];then
       systemctl start ${SERVICE}
else
    uname | grep AIX > /dev/null
    if [ $? -eq 0 ]; then
    	/usr/bin/startsrc -a '-l' -s safed
    else
    	${INITDDIR}/${SERVICE_SCRIPT} start
    fi
fi
sleep 2

PID=`ps -e -u 0|fgrep safed|egrep -v fgrep|awk '{print $1}'`
if [ -z "$PID" ] ;  then
        echo "${AGENT_NAME} not running. Please check installation parameters."
        exit 1;
fi

echo "Done."
echo
if [ $INSTALL_TYPE -ne 2 ]; then
        echo "${AGENT_NAME} will also be activated after a reboot via the"
        echo "init.d/${SERVICE_SCRIPT} startup script."
	echo
	echo "Please connect to the local machine using your web browser"
	echo "using the following URL: http://"`hostname`":6161"
	echo "and a userid and password of 'admin/admin'"
	echo "Once connected, please CHANGE THE DEFAULT PASSWORD, configure"
	echo "any additonal audit objectives you require, and restart"
	echo "the audit server".
	echo ""
else
	echo "${AGENT_NAME} has been upgraded."
	echo ""
	echo "Recommend that you re-set the password used for admin"
	echo "remote access in order to take advantage of the new"
	echo "password scheme."
fi

exit 0

