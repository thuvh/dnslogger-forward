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

#ifndef FORWARD_H
#define FORWARD_H

#include "config.h"
#include "ipv4.h"

typedef struct
{
  char signature[8];
  ipv4_t nameserver;            /* in network byte order */
  char payload[512];
} forward_t;

#define FORWARD_SIGNATURE "DNSXFR01"

void forward_open (const char *hostname, uint16_t port);
/* Opens the UDP socket which sends data to HOSTNAME on PORT.
   Terminates on error. */

void forward_process (const char *buffer, size_t length);
/* Forwards a single DNS packet.  If the packet does not look like a
   valid one, it is dropped. */

extern int forward_authoritative_only;
/* If true, only forward authoritative answers. */

#endif /* FORWARD_H */
