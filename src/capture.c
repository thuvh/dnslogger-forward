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

#include "capture.h"
#include "log.h"
#include "ipv4.h"
#include "forward.h"

#include <pcap.h>
#include <unistd.h>

#ifndef HAVE_PCAP_BREAKLOOP
#error Your libpcap version does not support pcap_breakloop.
#error At least version 0.8 is required.
#endif

static const char* capture_interface;
static const char* capture_filter;
/* Stores the strings passed on the command line. */

static pcap_t *pcap = 0;
static char pcap_errbuf[PCAP_ERRBUF_SIZE];
static struct bpf_program pcap_filter;
static void callback (u_char *closure, const struct pcap_pkthdr *header, const u_char *packet);
/* Interface to libpcap. */

static unsigned pcap_link_layer;
/* Length of the link layer header. */

static void open_and_wait (void);
/* Tries to open the pcap library.  Waits in case of failure. */

void
capture_open (const char *interface, const char *filter)
{
  capture_interface = interface;
  capture_filter = filter;
}

void
capture_run (void)
{
  /* Try to open the device.  Continue if capturing failes by
     reopening the device. */
  for (;;)
    {
      open_and_wait ();

      if (pcap_loop (pcap, -1, callback, 0)  == -1)
        log_warn ("Capture loop terminated: %s.", pcap_geterr (pcap));
      else
        log_warn ("Capture loop terminated");
    }
}

static
void open_and_wait (void)
{
  /* Count the number of retries.  During the first call, a filter
     expression error is fatal. */
  static unsigned retries = 0;
#define LOG_MAYBE_FATAL(X) do { if (retries == 1) log_fatal X; else log_warn X; sleep (5); } while (0)

  ++retries;
  for (;;) {

    /* Close the pcap interface if it is not already open. */
    if (pcap != 0)
      {
        pcap_close (pcap);
        pcap_freecode (&pcap_filter);
        pcap = 0;
      }

    /* Open the device.  Try again until success. */
    pcap = pcap_open_live (capture_interface, 65535, 1, 0, pcap_errbuf);
    if (UNLIKELY (pcap == 0)) {
      if (capture_interface)
        log_warn ("Could not open capture device '%s': %s.", capture_interface, pcap_errbuf);
      else
        log_warn ("Could not open capture device: %s.", pcap_errbuf);

      /* Sleep a bit so that our busy-waiting approach does not really
         hurt. */
      sleep (5);
      continue;
    }

    /* Now try to set the filter expression.  Here, a failure is fatal
       if we are trying for the first time. */
    if (pcap_compile (pcap, &pcap_filter, (char *)capture_filter, 1, 0) == -1)
      {
        LOG_MAYBE_FATAL (("Could not compile filter program '%s': %s.", capture_filter, pcap_geterr (pcap)));
        continue;
      }
    if (pcap_setfilter (pcap, &pcap_filter) == -1)
      {
        LOG_MAYBE_FATAL (("Could not apply filter programs '%s': %s.", capture_filter, pcap_geterr (pcap)));
        continue;
      }

    /* Determine the link layer type and the number of bytes in the header. */
    switch (pcap_datalink(pcap))
      {
      case DLT_EN10MB:
        pcap_link_layer = 14;
        break;

      case DLT_LINUX_SLL:
        pcap_link_layer = 16;
        break;

      default:
#ifdef HAVE_PCAP_DATALINK_VAL_TO_NAME
        log_fatal ("Could not determine link layer header length for %s (%d).",
                   pcap_datalink_val_to_name(pcap_datalink(pcap)), pcap_datalink(pcap));
#else
        log_fatal ("Could not determine link layer header length for link type %d.",
                   pcap_datalink(pcap));
#endif
      }

    /* We have successfully set up the capture process. */
    break;
  }
}

static void
callback (u_char *closure, const struct pcap_pkthdr *header, const u_char *packet)
{
  /* Check that we have capture enough bytes to cover the link layer
     header. */
  size_t size = header->caplen;
  if (UNLIKELY (size < pcap_link_layer))
    return;
  SKIP_BUFFER (packet, size, pcap_link_layer);

  /* Parse the packet and forward it if necessary. */
  forward_process (packet, size);
}
