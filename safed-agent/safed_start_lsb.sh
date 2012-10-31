#! /bin/sh
### BEGIN INIT INFO
# Provides:          safed
# Required-Start:    $syslog $network
# Required-Stop:     $network
# X-Stop-After:      sendsigs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: safed agent
# Description:       safed is an agent that allows to monitor log files for the presence of some given patterns,
#                    and send these lines to a syslog server, providing high reliability, performance and security. 
### END INIT INFO

#
# Author: Marco Sperini <severino.sperinil@wuerth-phoenix.com>
#

# PATH should only include /usr/* if it runs after the mountnfs.sh script
PATH=/sbin:/usr/sbin:/bin:/usr/bin
DESC="safed agent"
NAME=safed

SAFED=safed
SAFED_BIN=/usr/bin/safed
SAFED_OPTIONS="-d"
SAFED_PIDFILE=/var/run/safed.pid

SCRIPTNAME=/etc/init.d/$NAME

# Exit if the package is not installed
[ -x "$SAFED_BIN" ] || exit 0

# Read configuration variable file if it is present
[ -r /etc/default/$NAME ] && . /etc/default/$NAME

# Define LSB log_* functions.
. /lib/lsb/init-functions

do_start()
{
        DAEMON="$SAFED_BIN"
        DAEMON_ARGS="$SAFED_OPTIONS"
        PIDFILE="$SAFED_PIDFILE"

        # Return
        #   0 if daemon has been started
        #   1 if daemon was already running
        #   other if daemon could not be started or a failure occured
        start-stop-daemon --start --quiet --pidfile $PIDFILE --exec $DAEMON -- $DAEMON_ARGS
}

do_stop()
{
        NAME="$SAFED"
        PIDFILE="$SAFED_PIDFILE"

        # Return
        #   0 if daemon has been stopped
        #   1 if daemon was already stopped
        #   other if daemon could not be stopped or a failure occurred
        start-stop-daemon --stop --quiet --retry=TERM/30/KILL/5 --pidfile $PIDFILE --name $NAME
}

case "$1" in
  start)
        log_daemon_msg "Starting $DESC" "$SAFED"
        do_start
        case "$?" in
                0) log_end_msg 0 ;;
                1) log_progress_msg "already started"
                   log_end_msg 0 ;;
                *) log_end_msg 1 ;;
        esac

        ;;
  stop)
        log_daemon_msg "Stopping $DESC" "$SAFED"
        do_stop
        case "$?" in
                0) log_end_msg 0 ;;
                1) log_progress_msg "already stopped"
                   log_end_msg 0 ;;
                *) log_end_msg 1 ;;
        esac

        ;;
  reload|force-reload)
        log_daemon_msg "Reloading $DESC" "$SAFED"
        $0 stop
        $0 start
        log_end_msg $?
        ;;
  restart)
        $0 stop
        $0 start
        ;;
  status)
	# Is there a way to determine the status of a process considering both the pidfile and the executable pathname?
	# Actually, we are using only the executable pathname
        # status_of_proc -p $SAFED_PIDFILE $SAFED_BIN $SAFED && exit 0 || exit $?
	status_of_proc $SAFED_BIN $SAFED && exit 0 || exit $?
        ;;
  *)
        echo "Usage: $SCRIPTNAME {start|stop|restart|reload|force-reload|status}" >&2
        exit 3
        ;;
esac
