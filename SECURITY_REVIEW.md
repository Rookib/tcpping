# TCP-safe Agent Security Review

## Remote-control boundary

The Komari panel contains remote-terminal and remote-execution features for
compatible agents. This derivative agent does not implement their handlers and
does not advertise those capabilities. Its server-supplied capability list is
exactly `ping`, and that handler accepts only allow-listed TCP targets after
DNS pinning, public-IP validation, port validation, timeout enforcement, and
rate limiting.

IPv6 probes are restricted to the reviewed IANA RIR allocations inside
`2000::/3`, minus special-purpose prefixes. NAT64, Teredo, 6to4, ORCHID,
benchmarking, protocol anycast exceptions, documentation, and unallocated
IPv6 ranges are rejected. IPv4-mapped addresses retain the IPv4 checks.
DNS is resolved once; every returned address is validated before the first
validated address is dialed. Tests use injected lookup/dial functions and
`net.Pipe`, so the safety regressions do not query DNS or contact real hosts.

CI refuses to build if the patched `server` package contains an exec/terminal
handler, unexpected command execution, or a capability broader than constrained
TCP ping. Permitted command execution paths are:

- `server/vnstat.go`: fixed `vnstat --json` with a timeout.
- `server/ssh_login_watch.go`: fixed read-only `journalctl -f -n 0 -o cat`
  when file-based successful-login logs are unavailable.
- `server/ssh_auth_guard.go`: fixed read-only
  `journalctl -u ssh -u sshd -f -o short-iso`, and fixed `nft` operations.

The panel cannot change the collector executables or their arguments. Firewall
actions are restricted to `ban`/`unban`, a parsed single IP address, and a numeric
duration. The table, chain, sets, and rule structure are compiled in; no shell
or arbitrary command argument list is accepted. Upstream
self-update is forcibly disabled so it cannot replace this reviewed binary with
a different build.

## SSH login notifications

The optional SSH watcher is outbound-only. It reads new successful `sshd`
`Accepted` records from `/var/log/auth.log` or `/var/log/secure`; if those
files do not exist, it follows systemd journal with the fixed command above.
It skips all existing records at startup and sends a fixed JSON structure
containing only:

- username;
- source IP and source port;
- authentication method;
- timestamp.

It does not collect passwords, keys, commands, or session contents. It does
not edit PAM or SSH configuration and contains no remotely controlled
command-execution path.

## Failed-login detection and firewall actions

The SSH guard aggregates failed-login records using a configured threshold,
window, and cooldown, with optional aggregation by source IP. It does not read
passwords, private keys, or session contents. Silent mode keeps event detection
and reporting active while the panel controls notification delivery.

The installer enables an outbound-only security-action poller. It requests
queued actions for its own node token, applies only validated single-IP
`ban`/`unban` operations, and acknowledges the result. Bans respect the local
IP/CIDR whitelist. nftables operations use the fixed `inet komari_auth_guard`
table and TCP port 22; they do not configure a general remote firewall API.
Autonomous bans are disabled by default. When explicitly enabled, password
failures can trigger an immediate ban, while other failure methods use the
configured threshold. `--ssh-auth-ban-dry-run` avoids applying nftables changes.

## vnStat traffic accounting

The optional vnStat reporter is outbound-only. If the local `vnstat` binary is
installed, the agent runs `vnstat --json`, prefers the default-route interface,
otherwise the largest non-virtual interface counter (falling back to all
interfaces), and reports only interface name, cumulative rx/tx
counters, and daily rx/tx buckets. Missing vnStat is treated as unavailable and
does not break normal metric reporting.

## Residual risks

- The IPv6 policy is a reviewed allocation snapshot, not a live routing
  database. Newly allocated RIR ranges remain blocked until a reviewed
  release updates the snapshot. Network-specific address translation inside
  an otherwise ordinary global allocation cannot be inferred from the IP
  address alone; keep hostname allow-lists narrow.

- The agent runs as root to read system metrics and protected authentication
  logs. A vulnerability in its parsers or dependencies would therefore have a
  high local impact.
- Some metric collectors invoke fixed local utilities such as `free`, `uname`,
  or GPU tools. Their executable names and arguments are compiled in and are
  never supplied by the panel.
- GitHub repository or release compromise remains a supply-chain risk. Release
  downloads are checked against the release `SHA256SUMS`, which detects
  corruption but is not an independent signature authority.
- A stolen node token can submit forged metrics and security events and
  interfere with queue acknowledgements for that node, but cannot make this
  agent execute a shell command. A compromised panel can request the fixed
  firewall actions; keeping this queue enabled is a separate trust decision
  from permitting TCP probes.

## Operational recommendations

- Protect the panel and GitHub accounts with MFA.
- Rotate a node token if it is exposed.
- Keep TCP probe host and port allow-lists narrow.
- Review release commits before upgrading and retain the automatic binary
  backup made by the upgrade script.
