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

#ifndef CAPTURE_H
#define CAPTURE_H

#include "config.h"

void capture_open (const char *interface, const char *filter);
/* Opens INTERFACE, with filter expression FILTER.  Note that
   INTERFACE and FILTER are usually not checked immediately.
   INTERFACE may be a null pointer, to indicate the default
   interface. */

void capture_run (void);
/* Starts capturing (and forwarding) packets. */

#endif /* CAPTURE_H */
