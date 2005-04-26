/* dnslogger-forward - Forward DNS traffic for analysis
 * Copyright (C) 2005 Florian Weimer
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
/* The on-the-wire header.  When forwarding over TCP, a 16-bit
   big-endian length field is added. */

#define FORWARD_SIGNATURE "DNSXFR01"

void forward_target (const char *hostname, uint16_t port);
/* Sets the forward target to PORT at HOSTNAME.  Terminates on error
   (e.g. if HOSTNAME cannot be parsed). */

int forward_open (void);
/* Create the socket used for forwarding.  Returns 0 on sucess, -1 on
   failure. */

int forward_process (const char *buffer, size_t length);
/* Forwards a single DNS packet.  If the packet does not look like a
   valid one, it is dropped.  Returns nonzero if the packet has actually
   been forwarded, zero if it has been discarded. */

extern int forward_authoritative_only;
/* If true, only forward authoritative answers.  (The default is
   false.) */

extern int forward_without_answers;
/* If true, forward packets without answers (the default). */

extern int forward_over_tcp;
/* If true, use TCP to forward data instead of UDP. */


#endif /* FORWARD_H */
