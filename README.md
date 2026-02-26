# neighbot

**Network neighbor monitoring daemon.**
Passively watches ARP and NDP traffic on all Ethernet interfaces, records
IP-to-MAC mappings, and alerts you when something changes.

Like [arpwatch](https://ee.lbl.gov/), but also handles IPv6 and runs on
Linux, FreeBSD, OpenBSD, and NetBSD.

## Features

| | |
|---|---|
| **Protocols** | ARP (IPv4), NDP (IPv6) |
| **Events** | New stations, MAC changes, flip-flops, reappearances, bogons, moves |
| **Notifications** | Email via sendmail with hostname, vendor, and timestamps |
| **Active probing** | ARP requests / NDP solicitations to detect moved vs. multi-homed hosts |
| **OUI database** | Optional hardware vendor identification from MAC prefix |
| **Storage** | Plain CSV with atomic saves (temp file + rename) |
| **Sandboxing** | `pledge(2)` + `unveil(2)` on OpenBSD, privilege drop everywhere |
| **Portability** | Linux (glibc, musl), FreeBSD, OpenBSD, NetBSD |

Single-threaded, single binary, no dependencies beyond libpcap.

## Quick Start

```sh
make
sudo ./neighbot -q -f /tmp/neighbot.csv
```

Then generate some traffic (`arping`, `ping`) and watch the log output.

## Build

Requires a C compiler and libpcap.

| OS | Install libpcap |
|----|-----------------|
| Debian / Ubuntu | `apt install libpcap-dev` |
| Alpine | `apk add libpcap-dev` |
| Fedora / RHEL | `dnf install libpcap-devel` |
| FreeBSD / OpenBSD / NetBSD | included in base |

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

Uninstall:

```sh
sudo make uninstall
```

### Pre-built packages

`.deb` and `.rpm` packages are built automatically for each GitHub release
and attached as release assets. Supported distributions:

| Format | Distributions |
|--------|---------------|
| `.deb` | Ubuntu (stable, LTS), Debian (stable, oldstable) |
| `.rpm` | Fedora, Rocky Linux (2 versions), openSUSE Leap, SUSE BCI |
| `.apk` | Alpine Linux |

Install with your package manager:

```sh
sudo dpkg -i neighbot_*.deb        # Debian/Ubuntu
sudo rpm -i neighbot-*.rpm         # Fedora/RHEL/SUSE
sudo apk add --allow-untrusted neighbot-*.apk  # Alpine
```

## Usage

```
neighbot [-B seconds] [-d] [-f dbfile] [-i iface] [-m mailto] [-o ouifile] [-p] [-q] [-r] [-s sendmail] [-u user] [-V]
```

| Flag | Description |
|------|-------------|
| `-B seconds` | Bogon notification cooldown in seconds (default: 1800). Set to 0 for no rate limiting |
| `-d` | Daemonize (log to syslog instead of stderr) |
| `-f path` | Database file (default: `/var/neighbot/neighbot.csv`) |
| `-i iface` | Monitor only this interface (default: all Ethernet interfaces) |
| `-m addr` | Email recipient (default: `root`) |
| `-o path` | OUI vendor database file (default: `/var/neighbot/oui.txt`) |
| `-p` | Disable active probing (passive only) |
| `-q` | Quiet mode. No email notifications, events are still logged |
| `-r` | Report mode. Print database summary to stdout (or email with `-m`), then exit |
| `-s path` | Path to sendmail-compatible MTA (default: `/usr/sbin/sendmail`) |
| `-u user` | Drop privileges to this user after opening pcap handles (default: `nobody`) |
| `-V` | Print the version number and exit |

### Examples

```sh
# Foreground, quiet, custom DB
sudo neighbot -q -f /tmp/neighbot.csv

# Daemon with email alerts
sudo neighbot -d -u neighbot -m admin@example.com

# Single interface, no probing
sudo neighbot -d -i eth0 -p

# Print database report to stdout
neighbot -r -f /var/neighbot/neighbot.csv

# Email database report
neighbot -r -m admin@example.com
```

## Event Types

| Event | Description | Email |
|-------|-------------|-------|
| **new** | Previously unknown IP address seen for the first time | yes (suppressed for IPv6 temporary address rotations) |
| **changed** | IP seen with a different MAC than previously recorded | yes |
| **flip-flop** | IP alternates between two known MACs (VRRP/HSRP, dual-homing, or spoofing) | yes |
| **reappeared** | Known MAC/IP pair seen again after 6+ months of silence | yes |
| **bogon** | IP outside any local subnet on the receiving interface (possible spoofing) | yes |
| **moved** | MAC seen at a new IP while old IP no longer responds to probes | yes |

## Active Probing

When a known MAC appears at a new IP, neighbot sends up to 3 probes (5s
timeout each) to each old IP of the same address family associated with that
MAC (dual-stack hosts are not probed across IPv4/IPv6):

- **IPv4**: ARP request with sender IP `0.0.0.0` (RFC 5227)
- **IPv6**: NDP Neighbor Solicitation with source `::`

This avoids polluting the target's neighbor cache.

| Outcome | Meaning | Action |
|---------|---------|--------|
| Probe answered | Device has multiple IPs | Log only |
| Probe timed out | Device moved to new IP | Log + email |

Link-local addresses (fe80::/10, 169.254/16) are excluded from probing
since every IPv6 interface has one alongside its global address.

**IPv6 temporary addresses (RFC 4941):** When a device using privacy
extensions rotates its temporary address, neighbot detects that the same
MAC already has a non-EUI-64 address in the same /64 prefix and suppresses
the "new station" email.  The old temporary address is probed, and if it no
longer responds, a "moved" notification is sent instead.

Disable with `-p` for purely passive monitoring.

## Service Setup

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

## OUI Database

The OUI vendor database is installed by `make install` to
`/var/neighbot/oui.txt` and loaded once at startup.

Two file formats are supported:

| Format | Example | Source |
|--------|---------|--------|
| neighbot | `aa:bb:cc Vendor Name` | `make oui.txt` |
| arp-scan | `AABBCC\tVendor Name` | `net/arp-scan,-mac` package |

On OpenBSD, install the `arp-scan,-mac` package and point neighbot at
`/usr/local/share/arp-scan/ieee-oui.txt`.

To keep the bundled format current, add a daily cron job:

```sh
0 3 * * * curl -sL https://standards-oui.ieee.org/oui/oui.txt \
  | awk '/\(hex\)/ { gsub(/-/,":",$1); v=""; for(i=3;i<=NF;i++) v=v(i>3?" ":"")$i; print tolower($1)" "v }' \
  > /var/neighbot/oui.txt
```

neighbot will pick up the new data on its next restart.

## Database Format

Plain CSV stored at `/var/neighbot/neighbot.csv` by default:

```
ip,mac,interface,first_seen,last_seen,prev_mac
192.168.1.1,aa:bb:cc:dd:ee:ff,eth0,2026-02-23T14:30:00,2026-02-23T15:12:00,00:00:00:00:00:00
fe80::1,11:22:33:44:55:66,eth0,2026-02-23T14:30:05,2026-02-23T15:12:05,00:00:00:00:00:00
```

Timestamps are ISO 8601, local time. The `prev_mac` field stores the
previous MAC address for flip-flop detection. Old database files without
this field are loaded without errors.

Saves are atomic (write to temp file + rename). The entry limit is
100,000 to prevent memory exhaustion from spoofed traffic.

## Signals

| Signal | Action |
|--------|--------|
| `SIGHUP` | Save database to disk |
| `SIGTERM` / `SIGINT` | Save database and exit |
| `SIGUSR1` | Dump active probe state to the log |
| `SIGPIPE` | Ignored |

## Security

neighbot drops to an unprivileged user (default: `nobody`) after opening
pcap handles. All supplementary groups are dropped. The database directory
and file are chowned to the target user before switching.

On OpenBSD, neighbot additionally restricts itself using `pledge(2)` and
`unveil(2)`:

| Mode | pledge | unveil |
|------|--------|--------|
| Quiet (`-q`) | `stdio rpath wpath cpath` | DB directory only |
| With email | `stdio rpath wpath cpath proc exec dns` | disabled |

All pcap/BPF handles are opened before pledge, so no `bpf` promise is needed.

## Testing

Standalone test harnesses exercise the parser, database loader, OUI loader,
and probe packet builders with known inputs. They link without sanitizers so
they can run under valgrind.

```sh
make test                              # build all test binaries
tests/test_parse                       # run parser tests
tests/test_dbload                      # run database loader tests
tests/test_ouiload                     # run OUI loader tests
tests/test_probe                       # run probe builder and state machine tests
tests/test_capture                     # run capture_is_local subnet tests
make test-clean                        # remove test binaries
```

With valgrind:

```sh
valgrind --leak-check=full --error-exitcode=1 tests/test_parse
valgrind --leak-check=full --error-exitcode=1 tests/test_dbload
valgrind --leak-check=full --error-exitcode=1 tests/test_ouiload
valgrind --leak-check=full --error-exitcode=1 tests/test_probe
valgrind --leak-check=full --error-exitcode=1 tests/test_capture
```

A CI workflow (`.github/workflows/valgrind.yml`) runs all tests under valgrind
on every push and pull request.

## Fuzzing

Requires clang with libFuzzer support (included in most clang packages).

```sh
make fuzz                              # build all three fuzz targets
./fuzz_parse -max_total_time=60        # fuzz the packet parser for 60s
./fuzz_dbload -max_total_time=60       # fuzz the CSV database loader
./fuzz_ouiload -max_total_time=60      # fuzz the OUI file loader
make fuzz-clean                        # remove fuzz binaries
```

Each target is built with ASan and UBSan enabled.
Crashes and slow inputs are written to the current directory.

## How It Works

1. Enumerates non-loopback Ethernet interfaces via `pcap_findalldevs()`
2. Opens one pcap handle per interface with BPF filter:
   `arp or (icmp6 and (ip6[40] == 136 or ip6[40] == 135))`
3. Main loop: `poll()` on all handles (1s timeout)
4. **ARP**: extracts sender IP + MAC from requests/replies (skips probes)
5. **NDP**: parses Neighbor Advertisements (type 136) and Solicitations
   (type 135) for link-layer address options (skips DAD)
6. Updates an in-memory hash table; on new/changed entries, logs and
   optionally emails via `fork()`/`exec()` of sendmail

## License

BSD 2-Clause. See [LICENSE](LICENSE).
