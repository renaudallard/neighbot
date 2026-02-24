# neighbot

**Network neighbor monitoring daemon.** Passively watches ARP and NDP traffic
on all Ethernet interfaces, records IP-to-MAC mappings, and alerts you when
something changes.

Like [arpwatch](https://ee.lbl.gov/), but also handles IPv6 and runs on Linux and OpenBSD.

---

## Features

- Monitors **ARP** (IPv4) and **NDP** (IPv6) on all Ethernet interfaces
- Detects **new stations**, **MAC address changes**, **flip-flops**, **reappearances**, and **bogons** (IPs outside local subnets)
- Email alerts via sendmail with hostname, vendor, and timestamps
- Optional OUI database for hardware vendor identification
- Simple CSV database with atomic saves
- Single-threaded, single binary, no dependencies beyond libpcap
- Runs as a foreground process or daemon (syslog)
- `pledge(2)` and `unveil(2)` support on OpenBSD
- Portable: Linux (glibc, musl), FreeBSD, OpenBSD, NetBSD

## Quick start

```sh
make
sudo ./neighbot -q -f /tmp/neighbot.csv
```

Then generate some traffic (`arping`, `ping`) and watch the log output.

## Build

Requires a C compiler and libpcap.

| OS | Install libpcap |
|----|-----------------|
| Debian/Ubuntu | `apt install libpcap-dev` |
| Alpine | `apk add libpcap-dev` |
| Fedora/RHEL | `dnf install libpcap-devel` |
| FreeBSD/OpenBSD | included in base |

```sh
make
```

## Install

```sh
sudo make install          # binary + man page + OUI database
sudo make install-systemd  # + systemd unit (Linux)
sudo make install-rcd      # + rc.d script (OpenBSD)
make oui-update            # re-download IEEE OUI database
```

Installs to `/usr/local/sbin` by default. Override with `PREFIX`:

```sh
sudo make PREFIX=/usr install
```

## Usage

```
neighbot [-d] [-f dbfile] [-m mailto] [-p] [-q] [-u user]
```

| Flag | Description |
|------|-------------|
| `-d` | Daemonize (log to syslog instead of stderr) |
| `-f path` | Database file (default: `/var/neighbot/neighbot.csv`) |
| `-m addr` | Email recipient (default: `root`) |
| `-p` | Disable active probing (passive only) |
| `-q` | Quiet mode -- no email, still logs |
| `-u user` | Drop privileges to `user` after opening pcap handles (default: `nobody`) |

### Examples

```sh
# foreground, quiet, custom DB
sudo neighbot -q -f /tmp/neighbot.csv

# daemon with email alerts, drop privileges
sudo neighbot -d -u neighbot -m admin@example.com
```

## Service setup

<details>
<summary><b>Linux (systemd)</b></summary>

```sh
sudo make install-systemd
sudo systemctl daemon-reload
sudo systemctl enable --now neighbot
```

Edit `/etc/systemd/system/neighbot.service` to change options
(e.g. add `-m admin@example.com` to `ExecStart`, remove `-q` to enable email).

</details>

<details>
<summary><b>OpenBSD (rc.d)</b></summary>

```sh
sudo make install-rcd
sudo rcctl enable neighbot
sudo rcctl start neighbot
```

Override flags in `/etc/rc.conf.local`:

```
neighbot_flags=-d -m admin@example.com
```

</details>

## OUI updates

The OUI vendor database is installed by `make install` and loaded once at
startup. To keep it current, add a daily cron job:

```
0 3 * * * curl -sL https://standards-oui.ieee.org/oui/oui.txt | awk '/\(hex\)/ { gsub(/-/, ":", $1); v=""; for (i=3; i<=NF; i++) v = v (i>3?" ":"") $i; print tolower($1) " " v }' > /var/neighbot/oui.txt
```

neighbot will pick up the new data on its next restart.

## Database format

Plain CSV stored at `/var/neighbot/neighbot.csv` by default:

```
192.168.1.1,aa:bb:cc:dd:ee:ff,eth0,2026-02-23T14:30:00,2026-02-23T15:12:00,00:00:00:00:00:00
fe80::1,11:22:33:44:55:66,eth0,2026-02-23T14:30:05,2026-02-23T15:12:05,00:00:00:00:00:00
```

Fields: `ip, mac, interface, first_seen, last_seen, prev_mac` (ISO 8601, local time).
The `prev_mac` field stores the previous MAC address for flip-flop detection.
Old database files without this field are loaded without errors.

Saves are atomic (write to temp file + rename). The maximum number of entries
is limited to 100,000 to prevent memory exhaustion from spoofed traffic.

## Signals

| Signal | Action |
|--------|--------|
| `SIGHUP` | Save database to disk |
| `SIGTERM` / `SIGINT` | Save database and exit |
| `SIGUSR1` | Dump active probe state to the log |
| `SIGPIPE` | Ignored |

## Security

neighbot always drops to an unprivileged user (default: `nobody`) after
opening pcap handles. All supplementary groups are dropped. The database
directory and file are chowned to the target user before switching.

On OpenBSD, neighbot additionally drops privileges after initialization
using `pledge(2)` and `unveil(2)`:

| Mode | pledge | unveil |
|------|--------|--------|
| Quiet (`-q`) | `stdio rpath wpath cpath` | DB directory only |
| With email | `stdio rpath wpath cpath proc exec dns` | disabled (sendmail needs filesystem access) |

All pcap/BPF handles are opened before pledge, so no `bpf` promise is needed.

## Active probing

By default, neighbot actively probes old IP addresses to distinguish between
a device that **moved** (old IP no longer responds) and a device with
**multiple IPs** (both still active).

When a known MAC appears at a new IP, neighbot sends up to 3 probes (ARP
requests for IPv4, NDP Neighbor Solicitations for IPv6) to each old IP with a
5-second timeout per attempt. Probes use a zero source address (RFC 5227 for
ARP, `::` for NDP) to avoid polluting the target's neighbor cache.

- **Probe answered**: device has multiple IPs (log only, no email)
- **Probe timed out**: device moved (log + email notification)

Use `-p` to disable probing and make neighbot purely passive.

## How it works

1. Enumerates non-loopback Ethernet interfaces via `pcap_findalldevs()`
2. Opens one pcap handle per interface with BPF filter:
   `arp or (icmp6 and (ip6[40] == 136 or ip6[40] == 135))`
3. Main loop: `poll()` on all handles (1s timeout)
4. **ARP**: extracts sender IP + MAC from requests/replies (skips probes)
5. **NDP**: parses Neighbor Advertisements (type 136) and Solicitations
   (type 135) for link-layer address options (skips DAD)
6. Updates an in-memory hash table; on new/changed entries, logs and
   optionally emails via `fork()`/`exec()` of `/usr/sbin/sendmail`

## License

BSD 2-Clause. See [LICENSE](LICENSE).
