/*
 * Copyright (c) 2026 Renaud Allard <renaud@allard.it>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <pcap.h>
#include <string.h>

#include "neighbot.h"
#include "capture.h"
#include "log.h"

int
capture_open_all(struct iface *ifaces, int max)
{
	pcap_if_t *alldevs, *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	int count = 0;

	if (pcap_findalldevs(&alldevs, errbuf) < 0) {
		log_err("pcap_findalldevs: %s", errbuf);
		return -1;
	}

	for (dev = alldevs; dev && count < max; dev = dev->next) {
		pcap_t *p;
		struct bpf_program bpf;
		int dlt;

		/* skip loopback */
		if (dev->flags & PCAP_IF_LOOPBACK)
			continue;

		p = pcap_create(dev->name, errbuf);
		if (!p) {
			log_err("pcap_create(%s): %s", dev->name, errbuf);
			continue;
		}

		pcap_set_snaplen(p, SNAP_LEN);
		pcap_set_promisc(p, 0);
		pcap_set_timeout(p, POLL_TIMEOUT_MS);

		/* immediate mode: deliver packets to poll() without
		 * waiting for BPF buffer timeout (needed on BSDs) */
		pcap_set_immediate_mode(p, 1);

		if (pcap_activate(p) < 0) {
			log_err("pcap_activate(%s): %s", dev->name,
			        pcap_geterr(p));
			pcap_close(p);
			continue;
		}

		/* only Ethernet interfaces */
		dlt = pcap_datalink(p);
		if (dlt != DLT_EN10MB) {
			pcap_close(p);
			continue;
		}

		if (pcap_compile(p, &bpf, BPF_FILTER, 1,
		                 PCAP_NETMASK_UNKNOWN) < 0) {
			log_err("pcap_compile(%s): %s", dev->name,
			        pcap_geterr(p));
			pcap_close(p);
			continue;
		}

		if (pcap_setfilter(p, &bpf) < 0) {
			log_err("pcap_setfilter(%s): %s", dev->name,
			        pcap_geterr(p));
			pcap_freecode(&bpf);
			pcap_close(p);
			continue;
		}

		pcap_freecode(&bpf);

		if (pcap_setnonblock(p, 1, errbuf) < 0) {
			log_err("pcap_setnonblock(%s): %s", dev->name, errbuf);
			pcap_close(p);
			continue;
		}

		snprintf(ifaces[count].name, sizeof(ifaces[count].name),
		         "%s", dev->name);
		ifaces[count].handle = p;
		ifaces[count].fd = pcap_get_selectable_fd(p);

		if (ifaces[count].fd < 0) {
			log_err("pcap_get_selectable_fd(%s): not supported",
			        dev->name);
			pcap_close(p);
			continue;
		}

		log_msg("monitoring %s", dev->name);
		count++;
	}

	pcap_freealldevs(alldevs);
	return count;
}

void
capture_close_all(struct iface *ifaces, int count)
{
	for (int i = 0; i < count; i++) {
		if (ifaces[i].handle) {
			pcap_close(ifaces[i].handle);
			ifaces[i].handle = NULL;
			ifaces[i].fd = -1;
		}
	}
}
