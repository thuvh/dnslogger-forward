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

#ifndef LOG_H
#define LOG_H

#include "config.h"
#include "ansidecl.h"

void log_set_program (const char* name);
/* Sets the name of this program to NAME.  It is prepended to the
   error messages. */

void log_warn (const char *format, ...) ATTRIBUTE_PRINTF_1;
/* Writes a warning message based on FORMAT. */

extern int log_debug_enable;
void log_debug (const char *format, ...) ATTRIBUTE_PRINTF_1;
/* Writes a debugging message based on FORMAT.  Only shown if
   log_debug_enable is true. */

#define LOG_DEBUG(X) do { if (UNLIKELY (log_debug_enable)) log_debug X; } while (0)
/* Version of log_debug that prevents the evaluation of its argument
   if log_debug_enable is false. */

void log_buffer (const char *msg, const void *buffer, size_t length);
/* Prints LENGTH bytes starting at BUFFER, explained by MSG. */

void log_fatal (const char *format, ...) ATTRIBUTE_NORETURN ATTRIBUTE_PRINTF_1;
/* Writes a message based on FORMAT to standard output and terminates
   the process. */

#endif /* LOG_H */
