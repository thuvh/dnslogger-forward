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

#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

static const char *program;

void
log_set_program (const char* name)
{
  program = name;
}

void
log_warn (const char *format, ...)
{
  va_list ap;

  va_start (ap, format);
  fprintf (stderr, "%s: ", program);
  vfprintf (stderr, format, ap);
  fputs ("\n", stderr);
  va_end (ap);
}

int log_debug_enable = 0;

void
log_debug (const char *format, ...)
{
  va_list ap;

  if (LIKELY (!log_debug_enable))
    return;

  va_start (ap, format);
  fprintf (stderr, "%s: debug: ", program);
  vfprintf (stderr, format, ap);
  fputs ("\n", stderr);
  va_end (ap);
}

void
log_buffer (const char *msg, const void *buffer, size_t length)
{
  const unsigned char *p = buffer;
  const unsigned char *end = p + length;
  fprintf (stderr, "%s: %s: ", program, msg);

  while (p != end)
    {
      fprintf (stderr, "%02x", *p);
      ++p;
    }

  fputs ("\n", stderr);
}

void
log_fatal (const char *format, ...)
{
  va_list ap;

  va_start (ap, format);
  fprintf (stderr, "%s: FATAL: ", program);
  vfprintf (stderr, format, ap);
  fputs ("\n", stderr);
  exit (1);
  va_end (ap);
}
