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

int forward_authoritative_only = 0;

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
      LOG_DEBUG (("Unexpected IP protocol %u (" IPV4_FORMAT " -> " IPV4_FORMAT ").",
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
      LOG_DEBUG (("Dropping question packet (" IPV4_FORMAT " -> " IPV4_FORMAT ").",
                  IPV4_FORMAT_ARGS (ip_header.source),
                  IPV4_FORMAT_ARGS (ip_header.destination)));
      return 0;
    }

  /* If in forward_authoritative_only mode, exit if the packet is not an
     authoritative answer. */
  authoritative = DNS_AUTHORITATIVE_P (dns_header);
  if (forward_authoritative_only && !authoritative)
    {
      LOG_DEBUG (("Dropping non-authoritative DNS packet (" IPV4_FORMAT " -> " IPV4_FORMAT ").",
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
      LOG_DEBUG (("Dropping overlong packet (" IPV4_FORMAT " -> " IPV4_FORMAT
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

static int dnslogger_fd;
/* File descriptor of the UDP socket leading to the dnslogger server. */

void
forward_open (const char *hostname, uint16_t port)
{
  struct sockaddr_in sin;

  memset (&sin, 0, sizeof (sin));
  sin.sin_family = AF_INET;
  sin.sin_port = htons (port);

  {
    unsigned a, b, c, d;
    if (sscanf ("%u.%u.%u.%u", hostname, &a, &b, &c, &d) == 4
        && a <= 255 && b <= 255 && c <= 255 && d <= 255)
      sin.sin_addr.s_addr = htonl ((a << 24) + (b << 16) + (c << 8) + d);
    else
      {
        struct hostent *h = gethostbyname (hostname);

        if (h == 0 || h->h_addrtype != AF_INET || *h->h_addr_list == 0)
          log_fatal ("No IPv4 address for host name: %s.", hostname);

        STATIC_MEMCPY (sin.sin_addr, *h->h_addr_list);
      }
  }

  dnslogger_fd = socket (AF_INET, SOCK_DGRAM, 0);
  if (dnslogger_fd == -1)
    log_fatal ("Socket creation failed: %s.", strerror(errno));

  if (connect (dnslogger_fd, (struct sockaddr *)&sin, sizeof (sin)) == -1)
    log_fatal ("Could not connect forwarding socket: %s.", strerror(errno));
}

void
forward_process (const char *buffer, size_t length)
{
  forward_t fwd;
  size_t fwd_length;

  if (LIKELY (forward_decode_encode (buffer, length, &fwd, &fwd_length)))
    {
      /* We ignore the return value because we cannot easily recover
         from this error because it is likely that operator
         intervention is required. */

      if (send (dnslogger_fd, &fwd, fwd_length, 0) == -1)
        LOG_DEBUG(("Forwarding %u bytes failed: %s.",
                   fwd_length, strerror (errno)));
      else
        LOG_DEBUG(("Forwarded %u bytes.", fwd_length));
    }
}
