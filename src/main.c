/* dnslogger-forward - Forward DNS traffic for analysis
 * Copyright (C) 2004 Florian Weimer
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "log.h"
#include "ansidecl.h"
#include "forward.h"
#include "capture.h"
#include "test.h"

#include "getopt.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

static void usage(void) ATTRIBUTE_NORETURN;

int
main (int argc, char **argv)
{
  int c;
  const char *opt_interface = 0;
  const char *opt_filter = "udp and port 53";
  unsigned port;
  int opt_test_mode = 0;

  log_set_program (PACKAGE_NAME);
  opterr = 0;

  while ((c = getopt (argc, argv, "Ab:Df:hi:L:tTv")) != -1)
    switch (c)
      {
      case 'A':
        forward_authoritative_only = 1;
        break;

      case 'b':
        forward_set_source (optarg);
        break;

    break;

      case 'D':
        forward_without_answers = 0;
        break;

      case 'f':
        if (*optarg)
          opt_filter = optarg;
        break;

      case 'h':
        usage ();
        break;

      case 'i':
        if (*optarg)
          opt_interface = optarg;
        break;

      case 'L':
        capture_log_interval = atoi (optarg);
        if (optarg <= 0)
          log_fatal ("Argument to -L must be a positive number.");
        break;

      case 't':
        forward_over_tcp = 1;
        break;

      case 'T':
        opt_test_mode = 1;
        break;

      case 'v':
        log_debug_enable = 1;
        break;

      default:
        log_fatal ("Unknown option '-%c'.  Use '-h' for help.", optopt);
      }

  if (opt_test_mode)
    {
      test_run ();
      return 0;
    }

  if (argc - optind != 2)
    usage ();

  if (sscanf (argv[optind + 1], "%u", &port) != 1)
    log_fatal ("Invalid port number '%s'.", argv[optind + 1]);

  forward_target (argv[optind], port);

  /* General initialization. */

#ifdef LOG_DAEMON
  openlog ("dnslogger-forward", LOG_PID, LOG_DAEMON);
#else
  openlog ("dnslogger-forward", LOG_PID, 0);
#endif

  signal (SIGPIPE, SIG_IGN);

  /* Start capturing packets. */

  capture_open (opt_interface, opt_filter);
  capture_run ();

  return 0;
}

static void
usage(void)
{
  puts (PACKAGE_STRING " - forward DNS traffic for analysis");
  puts ("Copyright (C) 2004 Florian Weimer <fw@deneb.enyo.de>");
  puts ("");
  puts ("usage: " PACKAGE_NAME " [OPTIONS...] HOST PORT");
  puts ("");
  puts ("HOST is the name of the host to which DNS packets should be");
  puts ("forwarded, and PORT is the destination port number to use.");
  puts ("");
  puts ("Options:");
  puts ("");
  puts ("  -i INTERFACE    interface to capture packets on");
  puts ("  -f EXPRESSION   filter expression (BPF syntax)");
  puts ("  -A              forward authoritative answers only");
  puts ("  -D              do not forward empty answers");
  puts ("  -t              forward data over TCP (default is UDP)");
  puts ("  -L SECS         write a checkpoint log entry every SECS seconds");
  puts ("  -T              enable testing mode (reads from standard input)");
  puts ("  -v              verbose output, include debugging messages");
  puts ("");
  puts ("  -h              this help message");
  puts ("");
  puts ("See the manpage for usage examples.  Please send bug reports to");
  puts ("<dnslogger-bugs@lists.enyo.de>.");
  exit (1);
}
