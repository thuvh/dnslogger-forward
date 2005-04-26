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
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned server_port;
static void start_server (void);
static void process_stdin (void);
static void read_result (int fd);
static void tcp_server (void);

static int server_fd;

void
test_run (void)
{
  log_debug_enable = 1;
  start_server ();
  forward_target ("127.0.0.1", server_port);
  forward_open ();
  process_stdin ();
  if (forward_over_tcp)
    wait (0);
  else
    read_result (server_fd);
}

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

  server_fd = socket (AF_INET, forward_over_tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
  if (server_fd == -1)
    log_fatal ("Could not create UDP server socket: %s.", strerror (errno));
  if (bind (server_fd, (struct sockaddr *)&sin, sizeof (sin)) == -1)
    log_fatal ("Could not bind UDP server socket: %s.", strerror (errno));

  /* Retrieve port information. */
  sin_size = sizeof (sin);
  if (getsockname (server_fd, (struct sockaddr *)&sin, &sin_size) == -1)
    log_fatal ("Could not retrieve UDP server port: %s.", strerror (errno));
  server_port = ntohs (sin.sin_port);

  if (forward_over_tcp)
    {
      int result;

      if (listen (server_fd, 0) < 0)
        log_fatal ("could not listen on server socket: %s", strerror (errno));

      result = fork ();
      if (result < 0)
        log_fatal ("could not fork TCP server: %s", strerror (errno));
      if (result == 0)
        {
          tcp_server ();
          _exit (0);
        }
    }
  else
    {
      /* UDP server.  Set non-blocking mode. */
      flags = fcntl (server_fd, F_GETFL, 0);
      if (flags == -1)
        log_fatal ("Could not retrieve UDP server socker flags: %s.",
                   strerror (errno));
      if (fcntl (server_fd, F_SETFL, flags | O_NONBLOCK) == -1)
        log_fatal ("Could not make UDP server socket non-blocking: %s.",
                   strerror (errno));
    }
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
read_result (int fd)
{
  char buffer[4096];
  size_t length;
  int result = read (fd, buffer, sizeof (buffer));

  if (result < 0)
    {
      if (LIKELY (errno == EAGAIN || errno == EWOULDBLOCK))
        {
          log_debug_maybe(("No data received."));
          return;
        }
      else
        log_fatal ("Cannot read from standard input: %s.",
                   strerror (errno));
    }

  length = result;
  /* If only very few bytes have been received, try again. */
  if (length < 12)
    if (read (fd, buffer + length, sizeof (buffer) - length) < 0)
      log_fatal ("could not receive tet packet: %s", strerror (errno));

  if (length == sizeof (buffer))
    log_fatal ("Buffer full when reading from socket.");

  log_buffer ("Received data", buffer, length);
}

static void
tcp_server (void)
{
  static const char banner[] = "dnslogger test server\r\n";
  int client_fd = accept (server_fd, 0, 0);

  if (client_fd < 0)
    log_fatal ("could not accept TCP connection: %s", strerror (errno));
  if (write (client_fd, banner, sizeof (banner) - 1) != sizeof (banner) - 1)
    log_fatal ("could not write server banner");
  read_result (client_fd);
}
