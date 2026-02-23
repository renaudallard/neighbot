# neighbot

**Network neighbor monitoring daemon.** Passively watches ARP and NDP traffic
on all Ethernet interfaces, records IP-to-MAC mappings, and alerts you when
something changes.

Like [arpwatch](https://ee.lbl.gov/), but also handles IPv6 and runs on Linux and OpenBSD.

---

## Features

- Monitors **ARP** (IPv4) and **NDP** (IPv6) on all Ethernet interfaces
- Detects **new stations** and **MAC address changes** (flip-flop, spoofing)
- Email alerts via sendmail, or quiet mode for logging only
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
sudo make install          # binary + man page
sudo make install-systemd  # + systemd unit (Linux)
sudo make install-rcd      # + rc.d script (OpenBSD)
```

Installs to `/usr/local/sbin` by default. Override with `PREFIX`:

```sh
sudo make PREFIX=/usr install
```

## Usage

```
neighbot [-d] [-f dbfile] [-m mailto] [-q]
```

| Flag | Description |
|------|-------------|
| `-d` | Daemonize (log to syslog instead of stderr) |
| `-f path` | Database file (default: `/var/neighbot/neighbot.csv`) |
| `-m addr` | Email recipient (default: `root`) |
| `-q` | Quiet mode -- no email, still logs |

### Examples

```sh
# foreground, quiet, custom DB
sudo neighbot -q -f /tmp/neighbot.csv

# daemon with email alerts
sudo neighbot -d -m admin@example.com
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

## Database format

Plain CSV stored at `/var/neighbot/neighbot.csv` by default:

```
192.168.1.1,aa:bb:cc:dd:ee:ff,eth0,2026-02-23T14:30:00,2026-02-23T15:12:00
fe80::1,11:22:33:44:55:66,eth0,2026-02-23T14:30:05,2026-02-23T15:12:05
```

Fields: `ip, mac, interface, first_seen, last_seen` (ISO 8601, local time).

Saves are atomic (write to temp file + rename). The maximum number of entries
is limited to 100,000 to prevent memory exhaustion from spoofed traffic.

## Signals

| Signal | Action |
|--------|--------|
| `SIGHUP` | Save database to disk |
| `SIGTERM` / `SIGINT` | Save database and exit |
| `SIGPIPE` | Ignored |

## Security

On OpenBSD, neighbot drops privileges after initialization using
`pledge(2)` and `unveil(2)`:

| Mode | pledge | unveil |
|------|--------|--------|
| Quiet (`-q`) | `stdio wpath cpath` | DB directory only |
| With email | `stdio wpath cpath proc exec` | disabled (sendmail needs filesystem access) |

All pcap/BPF handles are opened before pledge, so no `bpf` promise is needed.

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

ISC (BSD 2-Clause). See [LICENSE](LICENSE).
