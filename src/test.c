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

#include "test.h"
#include "forward.h"
#include "log.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>

static unsigned server_port;
static void start_server (void);
static void process_stdin (void);
static void read_result (void);

void
test_run (void)
{
  log_debug_enable = 1;
  start_server ();
  forward_open ("127.0.0.1", server_port);
  process_stdin ();
  read_result ();
}

static int server_fd;

static void
start_server (void)
{
  struct sockaddr_in sin;
  socklen_t sin_size;
  int flags;

  memset (&sin, 0, sizeof (sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sin.sin_port = htons (0);

  server_fd = socket (AF_INET, SOCK_DGRAM, 0);
  if (server_fd == -1)
    log_fatal ("Could not create UDP server socket: %s.", strerror (errno));
  if (bind (server_fd, (struct sockaddr *)&sin, sizeof (sin)) == -1)
    log_fatal ("Could not bind UDP server socket: %s.", strerror (errno));

  /* Retrieve port information. */
  sin_size = sizeof (sin);
  if (getsockname (server_fd, (struct sockaddr *)&sin, &sin_size) == -1)
    log_fatal ("Could not retrieve UDP server port: %s.", strerror (errno));
  server_port = ntohs (sin.sin_port);

  /* Set non-blocking mode. */
  flags = fcntl (server_fd, F_GETFL, 0);
  if (flags == -1)
    log_fatal ("Could not retrieve UDP server socker flags: %s.",
               strerror (errno));
  if (fcntl (server_fd, F_SETFL, flags | O_NONBLOCK) == -1)
    log_fatal ("Could not make UDP server socket non-blocking: %s.",
               strerror (errno));
}

static void
process_stdin (void)
{
  char buffer[4096];
  int length = read (STDIN_FILENO, buffer, sizeof (buffer));
  if (length == -1)
    log_fatal ("Cannot read from standard input: %s.",
               strerror (errno));
  if (length == sizeof (buffer))
    log_fatal ("Buffer full when reading from standard input.");

  forward_process (buffer, length);
}

static void
read_result (void)
{
  char buffer[4096];
  int length = read (server_fd, buffer, sizeof (buffer));
  if (length == -1)
    {
      if (LIKELY (errno == EAGAIN || errno == EWOULDBLOCK))
        {
          LOG_DEBUG(("No data received."));
          return;
        }
      else
        log_fatal ("Cannot read from standard input: %s.",
                   strerror (errno));
    }
  if (length == sizeof (buffer))
    log_fatal ("Buffer full when reading from socket.");

  log_buffer ("Received data", buffer, length);
}
