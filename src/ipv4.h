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

#ifndef IPV4_H
#define IPV4_H

#include "config.h"

typedef uint32_t ipv4_t;
/* IPv4 address, in host byte order. */

#define IPV4_FORMAT "%u.%u.%u.%u"
#define IPV4_FORMAT_ARGS(X) (X) >> 24, ((X) >> 16) & 0xffU, ((X) >> 8) & 0xffU, (X) & 0xffU
/* Used to include IPv4 addresses in format strings. */

typedef struct
{
  uint8_t version_length;
  uint8_t tos;
  uint16_t total_length;
  uint16_t id;
  uint16_t fragmentation_offset;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t checksum;
  ipv4_t source;
  ipv4_t destination;
}  ipv4_header_t;
/* IPv4 header (without IP options). */

#define IPV4_HEADER_LENGTH(IP) (((IP).version_length & 0xF) * 4)
/* Extracts the length of the IP header, measured in octets. */

uint32_t ipv4_pseudo_header_checksum (const ipv4_header_t *header, uint16_t length);
/* Calculates the pseudo header checksum of HEADER, for a nested
   protocol data unit consisting of LENGTH octets.  (Note: Does not
   handle source routing for packets that are in transit.) */

uint16_t ipv4_checksum (const char *buffer, size_t length, uint32_t start);
/* Calculates the IPv4 checksum of BUFFER.  You can pass a pseudo
   header checksum in START (use zero if there is no pseudo
   header). */

int ipv4_header_decode (const char *packet, size_t length, ipv4_header_t *header);
/* Decodes an IPv4 header and stores the result in HEADER.  Returns
   zero on error. */

#define SKIP_BUFFER(BUF, LEN, SIZE) do { (BUF) += (SIZE); (LEN) -= (SIZE); } while (0);
/* Skips SIZE bytes at the beginning of BUF, decreasing LEN
   accordingly.  No check is performed that the new value of LEN is
   actually greater than zero. */

#define STATIC_MEMCPY(TARGET, SOURCE) memcpy (&(TARGET), (SOURCE), sizeof (TARGET))
/* Copies the beginning of SOURCE to TARGET. */

typedef struct {
  uint16_t source_port;
  uint16_t destination_port;
  uint16_t total_length;
  uint16_t checksum;
} udp_header_t;
/* A UDP header.  All fields are in host byte order. */

#define UDP_HEADER_LENGTH(UDP) ((void)(UDP).source_port, sizeof (udp_header_t))
/* Returns the size of a UDP header. */

int udp_header_decode (const char *packet, size_t length, const ipv4_header_t *ip_header, udp_header_t *header);
/* Decodes the UDP header at PACKET and stores the result in HEADER.
   Returns zero on error.  IP_HEADER is used to construct the
   pseudo-header.  */

#endif /* IPV4_H */
