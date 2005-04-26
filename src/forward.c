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

#include "dns.h"
#include "forward.h"
#include "log.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

int forward_authoritative_only = 0;
int forward_without_answers = 1;
int forward_over_tcp = 0;

/* Returns nonzero if the packet should be forwarded. */
static int
forward_decode_encode (const char* buffer, size_t length, forward_t *forward, size_t *forward_length)
{
  ipv4_header_t ip_header;
  udp_header_t udp_header;
  dns_header_t dns_header;
  int authoritative;

  if (UNLIKELY (!ipv4_header_decode (buffer, length, &ip_header)))
    return 0;
  length = ip_header.total_length;

  /* Check if we actually have a UDP packet. */
  if (UNLIKELY (ip_header.protocol != 17))
    {
      log_debug_maybe (("Unexpected IP protocol %u (" IPV4_FORMAT " -> " IPV4_FORMAT ").",
                  (unsigned)ip_header.protocol,
                  IPV4_FORMAT_ARGS (ip_header.source),
                  IPV4_FORMAT_ARGS (ip_header.destination)));
      return 0;
    }

  SKIP_BUFFER (buffer, length, IPV4_HEADER_LENGTH (ip_header));
  if (UNLIKELY (!udp_header_decode (buffer, length, &ip_header, &udp_header)))
    return 0;
  length = udp_header.total_length;

  SKIP_BUFFER (buffer, length, UDP_HEADER_LENGTH (udp_header));
  if (UNLIKELY (!dns_header_decode (buffer, length, &dns_header)))
    return 0;

  if (! DNS_ANSWER_P (dns_header))
    {
      log_debug_maybe (("Dropping question packet (" IPV4_FORMAT " -> " IPV4_FORMAT ").",
                        IPV4_FORMAT_ARGS (ip_header.source),
                        IPV4_FORMAT_ARGS (ip_header.destination)));
      return 0;
    }

  if (UNLIKELY ((!forward_without_answers) && dns_header.ancount == 0
                && !DNS_TRUNCATION_P (dns_header)))
    {
      log_debug_maybe (("Dropping packet without answers (" IPV4_FORMAT " -> " IPV4_FORMAT ").",
                        IPV4_FORMAT_ARGS (ip_header.source),
                        IPV4_FORMAT_ARGS (ip_header.destination)));
      return 0;
    }

  /* If in forward_authoritative_only mode, exit if the packet is not an
     authoritative answer. */
  authoritative = DNS_AUTHORITATIVE_P (dns_header);
  if (forward_authoritative_only && !authoritative)
    {
      log_debug_maybe (("Dropping non-authoritative DNS packet (" IPV4_FORMAT " -> " IPV4_FORMAT ").",
                        IPV4_FORMAT_ARGS (ip_header.source),
                        IPV4_FORMAT_ARGS (ip_header.destination)));
      return 0;
    }

  /* Add the DNSXFR01 protocol signature. */
  STATIC_MEMCPY (forward->signature, FORWARD_SIGNATURE);

  /* Copy the source IP address only if the AA flag is set, to protect
     submitter privacy. */
  if (authoritative)
    forward->nameserver = htonl (ip_header.source);
  else
    forward->nameserver = htonl (0);

  /* Guard the call to memcpy below. */
  if (UNLIKELY (length > sizeof (forward->payload)))
    {
      log_debug_maybe (("Dropping overlong packet (" IPV4_FORMAT " -> " IPV4_FORMAT
                        ", %u bytes).",
                        IPV4_FORMAT_ARGS (ip_header.source),
                        IPV4_FORMAT_ARGS (ip_header.destination),
                        length));
      return 0;
    }

  /* Copy the payload. */
  memcpy (&forward->payload, buffer, length);
  *forward_length
    = sizeof (forward->signature) + sizeof (forward->nameserver) + length;

  return 1;
}

static int dnslogger_fd = -1;
/* File descriptor of the UDP socket leading to the dnslogger server. */

struct sockaddr_in dnslogger_target;
/* The IPv4 address and port of the target to which we forward packets. */

void
forward_target (const char *hostname, uint16_t port)
{
  memset (&dnslogger_target, 0, sizeof (dnslogger_target));
  dnslogger_target.sin_family = AF_INET;
  dnslogger_target.sin_port = htons (port);

  {
    unsigned a, b, c, d;
    if (sscanf (hostname, "%u.%u.%u.%u", &a, &b, &c, &d) == 4
        && a <= 255 && b <= 255 && c <= 255 && d <= 255)
      dnslogger_target.sin_addr.s_addr = htonl ((a << 24) + (b << 16) + (c << 8) + d);
    else
      {
        struct hostent *h = gethostbyname (hostname);

        if (h == 0 || h->h_addrtype != AF_INET || *h->h_addr_list == 0)
          log_fatal ("No IPv4 address for host name: %s.", hostname);

        STATIC_MEMCPY (dnslogger_target.sin_addr, *h->h_addr_list);
      }
  }
}

int
forward_open (void)
{
  if (dnslogger_fd >= 0)
    close (dnslogger_fd);

  dnslogger_fd
    = socket (AF_INET, forward_over_tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
  if (dnslogger_fd == -1)
    {
      syslog (LOG_ERR, "%s socket creation failed: %s.",
              forward_over_tcp ? "TCP" : "UDP", strerror(errno));
      return -1;
    }

  if (connect (dnslogger_fd, (struct sockaddr *)&dnslogger_target,
               sizeof (dnslogger_target)) == -1)
    {
      syslog (LOG_ERR, "Could not connect forwarding socket: %s.", strerror(errno));
      goto error_out;
    }

  /* In TCP mode, read the service banner.  FIXME: Add a timeout. */

  if (forward_over_tcp)
    {
      char buf[256];
      char *p = buf;
      char *end = p + sizeof (buf);
      char *lf;
      ssize_t result;

      while (p != end)
        {
          result = read (dnslogger_fd, p, end - p);
          if (result < 0)
            {
              syslog (LOG_ERR, "Could not read remote banner: %s.",
                      strerror (errno));
              goto error_out;
            }
          if (result == 0)
            {
              syslog (LOG_ERR, "remote host closed the connection");
              goto error_out;
            }
          p += result;

          /* Look for  the CRLF terminator and strip it if it is there.
             Otherwise, continue reading. */

          lf = memchr (buf, '\n', end - buf);
          if (!lf)
            continue;
          *lf = 0;
          if (lf != buf && lf[-1] == '\r')
            {
              lf[-1] = 0;
              --lf;
            }

          /* Replace non-printable characters. */

          for (p = buf; p != lf; ++p)
            if (*p < ' ' || *p > '~')
              *p = '.';

          syslog (LOG_NOTICE, "connected to " IPV4_FORMAT ":%hu (TCP): %s",
                  IPV4_FORMAT_ARGS (htonl (dnslogger_target.sin_addr.s_addr)),
                  ntohs (dnslogger_target.sin_port),
                  buf);
          return 0;
        }

      syslog (LOG_ERR, "Remote service banner is too long.");
      goto error_out;
    }
  else
    {
      /* UDP mode needs no special setup. */

      syslog (LOG_NOTICE, "forwarding to " IPV4_FORMAT ":%hu (UDP)",
              IPV4_FORMAT_ARGS (ntohl (dnslogger_target.sin_addr.s_addr)),
              ntohs (dnslogger_target.sin_port));
      return 0;
    }

 error_out:
  close (dnslogger_fd);
  dnslogger_fd = -1;
  return -1;
}

static void
forceful_open (void)
{
  while (forward_open () < 0)
    sleep (5);
}

/* Write LENGTH bytes at BUF to STREAM.
   Returns 0 on success, -1 on failure. */
static int
forceful_write (int stream, const void *buf, size_t length)
{
  const char *p = buf;
  const char* end = p + length;
  ssize_t result;

  while (p != end)
    {
      result = write (stream, p, end - p);
      if (result < 0)
        return -1;
      p += result;
    }

  return 0;
}

int
forward_process (const char *buffer, size_t length)
{
  forward_t fwd;
  size_t fwd_length = 0;

  if (LIKELY (forward_decode_encode (buffer, length, &fwd, &fwd_length)))
    {
      if (UNLIKELY (dnslogger_fd < 0))
        forceful_open ();

      /* Keep sending packets until successful. */

      for (;;)
        {
          if (forward_over_tcp)
            {
              uint16_t len = htons (fwd_length);

              if (UNLIKELY (forceful_write (dnslogger_fd, &len, 2) < 0))
                {
                  syslog (LOG_ERR, "could not write record size: %s",
                        strerror (errno));
                goto retry;
              }

              if (UNLIKELY (forceful_write (dnslogger_fd, &fwd, fwd_length) < 0))
              {
                syslog (LOG_ERR, "could not write packet: %s",
                        strerror (errno));
                goto retry;
              }

              return 1;
            }
          else
            {
              /* UDP mode. */

              if (UNLIKELY (send (dnslogger_fd, &fwd, fwd_length, 0) < 0))
                {
                  syslog (LOG_ERR, "could not write packet: %s",
                          strerror (errno));
                  goto retry;
                }

              log_debug_maybe(("Forwarded %u bytes.", fwd_length));
              return 1;
            }
        retry:
          forceful_open ();
        }
    }
  else
    return 0;
}
