/*
 * Copyright (c) 2026 Renaud Allard <renaud@allard.it>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <ifaddrs.h>
#include <netinet/in.h>
#include <pcap.h>
#include <string.h>

#if defined(__linux__)
#include <linux/if_packet.h>
#else
#include <net/if_dl.h>
#endif

#include "neighbot.h"
#include "capture.h"
#include "log.h"

struct subnet {
	char    iface[32];
	int     af;
	uint8_t addr[16];
	uint8_t mask[16];
};

static struct subnet subnets[MAX_SUBNETS];
static int subnet_count;

static void
fill_local_macs(struct iface *ifaces, int count)
{
	struct ifaddrs *ifap, *ifa;

	if (getifaddrs(&ifap) < 0)
		return;

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr)
			continue;

#if defined(__linux__)
		if (ifa->ifa_addr->sa_family != AF_PACKET)
			continue;
		struct sockaddr_ll *sll =
		    (struct sockaddr_ll *)ifa->ifa_addr;
		if (sll->sll_halen != 6)
			continue;
		for (int i = 0; i < count; i++) {
			if (strcmp(ifaces[i].name, ifa->ifa_name) == 0) {
				memcpy(ifaces[i].local_mac,
				    sll->sll_addr, 6);
				break;
			}
		}
#else
		if (ifa->ifa_addr->sa_family != AF_LINK)
			continue;
		struct sockaddr_dl *sdl =
		    (struct sockaddr_dl *)ifa->ifa_addr;
		if (sdl->sdl_alen != 6)
			continue;
		for (int i = 0; i < count; i++) {
			if (strcmp(ifaces[i].name, ifa->ifa_name) == 0) {
				memcpy(ifaces[i].local_mac,
				    LLADDR(sdl), 6);
				break;
			}
		}
#endif
	}

	freeifaddrs(ifap);
}

static void
fill_local_subnets(struct iface *ifaces, int count)
{
	struct ifaddrs *ifap, *ifa;

	subnet_count = 0;

	if (getifaddrs(&ifap) < 0)
		return;

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		int af, alen;
		const uint8_t *addr, *mask;
		int found = 0;

		if (!ifa->ifa_addr || !ifa->ifa_netmask)
			continue;

		af = ifa->ifa_addr->sa_family;
		if (af == AF_INET) {
			struct sockaddr_in *sin =
			    (struct sockaddr_in *)ifa->ifa_addr;
			struct sockaddr_in *sinm =
			    (struct sockaddr_in *)ifa->ifa_netmask;
			addr = (const uint8_t *)&sin->sin_addr;
			mask = (const uint8_t *)&sinm->sin_addr;
			alen = 4;
		} else if (af == AF_INET6) {
			struct sockaddr_in6 *sin6 =
			    (struct sockaddr_in6 *)ifa->ifa_addr;
			struct sockaddr_in6 *sin6m =
			    (struct sockaddr_in6 *)ifa->ifa_netmask;
			addr = (const uint8_t *)&sin6->sin6_addr;
			mask = (const uint8_t *)&sin6m->sin6_addr;
			alen = 16;
		} else {
			continue;
		}

		/* only track subnets for monitored interfaces */
		for (int i = 0; i < count; i++) {
			if (strcmp(ifaces[i].name, ifa->ifa_name) == 0) {
				found = 1;
				break;
			}
		}
		if (!found)
			continue;

		if (subnet_count >= MAX_SUBNETS)
			break;

		struct subnet *s = &subnets[subnet_count];
		snprintf(s->iface, sizeof(s->iface), "%s", ifa->ifa_name);
		s->af = af;
		memset(s->addr, 0, sizeof(s->addr));
		memset(s->mask, 0, sizeof(s->mask));
		memcpy(s->addr, addr, alen);
		memcpy(s->mask, mask, alen);
		subnet_count++;
	}

	freeifaddrs(ifap);
}

int
capture_is_local(const char *iface, int af, const uint8_t *ip)
{
	int alen = (af == AF_INET) ? 4 : 16;
	int has_subnet = 0;

	for (int i = 0; i < subnet_count; i++) {
		struct subnet *s = &subnets[i];

		if (s->af != af || strcmp(s->iface, iface) != 0)
			continue;
		has_subnet = 1;

		int match = 1;
		for (int j = 0; j < alen; j++) {
			if ((ip[j] & s->mask[j]) !=
			    (s->addr[j] & s->mask[j])) {
				match = 0;
				break;
			}
		}
		if (match)
			return 1;
	}

	/* no configured subnets for this af. cannot determine locality */
	if (!has_subnet)
		return 1;

	return 0;
}

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

		/* filter by interface name if specified */
		if (cfg.iface && strcmp(dev->name, cfg.iface) != 0)
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
		memset(ifaces[count].local_mac, 0,
		    sizeof(ifaces[count].local_mac));

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
	fill_local_macs(ifaces, count);
	fill_local_subnets(ifaces, count);
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
