dnl Process this file with autoconf to produce a configure script.
AC_INIT([dnslogger-forward],[0.1.9],[fw@deneb.enyo.de])

AC_CANONICAL_TARGET
AC_EXEEXT

dnl Checks for programs.
AC_PROG_INSTALL
AC_PROG_CC

if test "$GCC" = "yes" ; then
  AC_SUBST([WARN_CFLAGS], "-Wall -Wformat-nonliteral")
fi

dnl for C compiler properties.
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdint.h])

dnl Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memcpy])

dnl Checks for libraries.
AC_SEARCH_LIBS(gethostbyname, nsl)
AC_SEARCH_LIBS(connect, socket)
AC_SEARCH_LIBS(pcap_open_live, pcap)

AC_CHECK_FUNCS([pcap_datalink_val_to_name])
AC_CHECK_FUNCS([pcap_breakloop])

dnl Handle <stdint.h>.
AH_BOTTOM([/* Include <stdint.h> where available.
   On other systems, hope that <sys/types.h> provides the necessary
   types. */

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <sys/types.h>
])

AC_CONFIG_SRCDIR([src/ipv4.c])
AC_CONFIG_HEADER(config.h)
AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([stamp-h], [echo timestamp > stamp-h])

AC_OUTPUT
