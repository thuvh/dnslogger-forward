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
#include "log.h"
#include "ipv4.h"
#include "ansidecl.h"

#include <netinet/in.h>
#include <string.h>

int
dns_header_decode (const char *packet, size_t length, dns_header_t *header)
{
  if (UNLIKELY (length < sizeof (*header)))
    {
      LOG_DEBUG (("Truncated DNS packet (length %u).", length));
      return 0;
    }

  /* Copy the header to the aligned struct. */
  STATIC_MEMCPY (*header, packet);

  header->serial = ntohs(header->serial);
  header->flags = ntohs(header->flags);
  header->qdcount = ntohs(header->qdcount);
  header->ancount = ntohs(header->ancount);
  header->nscount = ntohs(header->nscount);
  header->adcount = ntohs(header->adcount);

  return header->qdcount < 16 && header->ancount < 1024
    && header->nscount < 1024 && header->adcount < 1024;
}
