#! /bin/sh
#
# /etc/init.d/dnslogger-forward
#
# Based on a template written by Miquel van Smoorenburg
# <miquels@cistron.nl>, which was modified for Debian by Ian Murdock
# <imurdock@gnu.ai.mit.edu>.

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
DAEMON=/usr/sbin/dnslogger-forward
NAME=dnslogger-forward
DESC=dnslogger-forward
CONFIG=/etc/default/dnslogger-forward

test -x $DAEMON || exit 0

# Include dnslogger-forward defaults if available
if [ -f $CONFIG ] ; then
	. $CONFIG
fi

set -e

case "$1" in
  start)
	echo -n "Starting $DESC: "
	if test -z "$HOST" -o -z "$PORT" ; then
	    echo "You must configure HOST and PORT in $CONFIG."
	    exit 0
	fi
	start-stop-daemon --start --quiet --pidfile /var/run/$NAME.pid \
	    --make-pidfile --background --exec $DAEMON \
	    -- -i "$INTERFACE" -f "$FILTER" $OPTIONS "$HOST" "$PORT"
	echo "$NAME."
	;;
  stop)
	echo -n "Stopping $DESC: "
	start-stop-daemon --stop --quiet --pidfile /var/run/$NAME.pid \
		--exec $DAEMON
	echo "$NAME."
	;;
  restart|force-reload)
	echo -n "Restarting $DESC: "
	start-stop-daemon --stop --quiet --pidfile \
		/var/run/$NAME.pid --exec $DAEMON
	sleep 1
	start-stop-daemon --start --quiet --pidfile \
		/var/run/$NAME.pid --exec $DAEMON -- $DAEMON_OPTS
	echo "$NAME."
	;;
  *)
	N=/etc/init.d/$NAME
	echo "Usage: $N {start|stop|restart|force-reload}" >&2
	exit 1
	;;
esac

exit 0
