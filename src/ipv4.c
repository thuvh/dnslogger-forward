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

#include "ipv4.h"
#include "ansidecl.h"
#include "log.h"

#include <netinet/in.h>
#include <string.h>

int
ipv4_header_decode (const char *packet, size_t length, ipv4_header_t *header)
{
  /* Check minimum header length. */
  if (UNLIKELY (length < sizeof (*header)))
    {
      log_debug_maybe (("Short packet of length %u.", length));
      return 0;
    }

  /* Copy the header to the (aligned) struct. */
  STATIC_MEMCPY (*header, packet);

  /* Check IP version and minimum header length. */
  if (UNLIKELY ((header->version_length & 0xf0) != 0x40))
    {
      log_debug_maybe (("Non-IP packet, first byte is 0x%02x.", header->version_length));
      return 0;
    }

  if (UNLIKELY (IPV4_HEADER_LENGTH(*header) > length))
    {
      log_debug_maybe (("Truncated IP header, indicated length is %u, available is %u.",
                        IPV4_HEADER_LENGTH(*header), length));
      return 0;
    }

  /* The checksum vanishes if it is correct. */
  if (UNLIKELY (ipv4_checksum (packet, IPV4_HEADER_LENGTH(*header), 0) != 0))
    {
      log_debug_maybe (("Incorrect IP checksum (header length %u, packet length %u).",
                        IPV4_HEADER_LENGTH(*header), length));
      return 0;
    }

  /* Everything looks well.  Convert the fields that are in network
     byte order. */
  header->total_length = ntohs (header->total_length);
  header->id = ntohs (header->id);
  header->fragmentation_offset = ntohs (header->fragmentation_offset);
  header->checksum = ntohs (header->checksum);
  header->source = ntohl (header->source);
  header->destination = ntohl (header->destination);

  if (UNLIKELY (header->total_length > length))
    {
      log_debug_maybe (("Truncated IP packet, indicated length is %u, available is %u.",
                        header->total_length, length));
      return 0;
    }

  return 1;
}


uint32_t
ipv4_pseudo_header_checksum (const ipv4_header_t * header, uint16_t length)
{
  return (header->source >> 16) + (header->source & 0xFFFF)
    + (header->destination >> 16) + (header->destination & 0xFFFF)
    + header->protocol + length;
}

uint16_t
ipv4_checksum (const char *buffer, size_t length, uint32_t start)
{
  /* We have to read the buffer as a sequence of unsigned bytes. */
  const unsigned char *p = (unsigned char *)buffer;

  /* Points one byte past the end of the buffer. */
  const unsigned char *end;

  /* The final checksum. */
  uint32_t sum;

  /* The intermediate checksum counters.  We need 32 bits because we
     must preserve the higher bits to compensate for carries. */
  uint32_t a, b;
  a = 0; b = 0;


  /* If the buffer length is not even, we have to treat the trailing
     byte in a special way.  After that, the length is even. */
  if (length % 2)
    {
      --length;
      a = p[length];
    }

  /* Loop over all pairs of bytes. */
  end = p + length;
  while (p != end)
    {
      a += p[0];
      b += p[1];
      p += 2;
    }

  /* Combine both counters and return the value. */
  sum = (a << 8) + b;
  sum += start;
  return ~((sum & 0xFFFF) + (sum >> 16));
}

int
udp_header_decode (const char *packet, size_t length, const ipv4_header_t *ip_header, udp_header_t *header)
{
  /* Check minimum header length. */
  if (UNLIKELY (length < sizeof (*header)))
    {
      log_debug_maybe (("Truncated UDP header (" IPV4_FORMAT " -> " IPV4_FORMAT ").",
                        IPV4_FORMAT_ARGS (ip_header->source),
                        IPV4_FORMAT_ARGS (ip_header->destination)));
      return 0;
    }

  /* Copy the header to the aligned struct. */
  STATIC_MEMCPY(*header, packet);
  header->source_port = ntohs (header->source_port);
  header->destination_port = ntohs (header->destination_port);
  header->checksum = ntohs (header->checksum);
  header->total_length = ntohs (header->total_length);

  /* Check embedded length. */
  if (UNLIKELY (header->total_length > length))
    {
      log_debug_maybe (("Truncated UDP packet (" IPV4_FORMAT " -> " IPV4_FORMAT
                        ", UDP length %u, available %u).",
                        IPV4_FORMAT_ARGS (ip_header->source),
                        IPV4_FORMAT_ARGS (ip_header->destination),
                        header->total_length, length));
      return 0;
    }

  /* Checksum can be zero, indicating no checksumming. */
  if (UNLIKELY (header->checksum == 0))
    return 1;

  /* Calculate the checksum. */
  if (UNLIKELY (ipv4_checksum (packet, length, ipv4_pseudo_header_checksum (ip_header, header->total_length)) != 0))
    {
      log_debug_maybe (("UDP checksum mismatch (" IPV4_FORMAT " -> " IPV4_FORMAT
                        ", UDP length %u).",
                        IPV4_FORMAT_ARGS (ip_header->source),
                        IPV4_FORMAT_ARGS (ip_header->destination), header->total_length));
      return 0;
    }

  return 1;
}
