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

#ifndef DNS_H
#define DNS_H

#include "config.h"

typedef struct
{
  uint16_t serial;              /* 16 bit "unique" ID */
  uint16_t flags;
  uint16_t qdcount;             /* number of questions */
  uint16_t ancount;             /* number of answer records */
  uint16_t nscount;             /* number of authoritative records */
  uint16_t adcount;             /* number of additional records */
} dns_header_t;

#define DNS_ANSWER_P(DNS) ((DNS).flags & 0x8000)
/* Evaluates to a true value if DNS is a response packet. */

#define DNS_AUTHORITATIVE_P(DNS) (((DNS).flags & 0x8400) == 0x8400)
/* Evaluates to a true value if DNS is an authoritative response
   packet. */

#define DNS_TRUNCATION_P(DNS) ((DNS).flags & 0x0200)
/* Evaluates to a true value if DNS is a truncated packet. */

int dns_header_decode (const char *packet, size_t length, dns_header_t *header);
/* Parses LENGTH bytes at PACKET as a DNS header and stores the result
   at HEADER.  Returns zero on error. */

#endif /* DNS_H */
