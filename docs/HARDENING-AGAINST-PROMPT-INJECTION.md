# Hardening dbounce against prompt-injected agents

How to harden dbounce (and the rest of the Bounce suite) against a
prompt-injected agent that tries to disable the proxy before issuing
SQL. This doc is for SecOps + platform engineers deploying dbounce
on engineer laptops, analyst workstations, jump hosts, or CI runners.

---

## The honest framing

dbounce is a **user-process on a user-machine.** A prompt-injected
agent that has shell access on the same machine — through a tool
primitive like `bash`/`exec`/`python -c`, or simply by writing a
shim script the user then runs — can `pkill dbounce`,
`unset PGHOST` / `unset DATABASE_URL`, set a fresh `DATABASE_URL`
pointing straight at the database, or just open a connection to the
real DB on its native port with a freshly-built psycopg2 / mysql.Conn
client. dbounce by itself cannot stop any of those moves.

What dbounce CAN do is make every disable-attempt **detectable** and
make the bypass **costly** when composed with the rest of an
operator's defense-in-depth stack:

- Heartbeat events emitted to the audit pipeline so a gap is visible
  within seconds (per the `heartbeat_gap` alert rule shipped in
  Slice 2).
- Tamper-detection on the audit chain (hash-chained rows; a gap or
  rewrite shows up at `dbounce audit verify`).
- Admin-action audit events so attempts to mutate the rule set,
  install a malicious profile, or change modes are themselves
  audited.

The rest of this doc walks through the **six-layer defense** that, in
combination, actually prevents (or at minimum reliably detects) the
disable-bouncer attack. dbounce is **one layer.** The other five are
the customer's OS, network, sandbox, and MDM tooling — not things
dbounce ships.

---

## The 6-layer defense

### Layer 1 — Don't give the agent shell access

**Strongest layer.** If the agent has no shell primitive, it can't
run `pkill`, can't `unset` an env var in the parent process, and
can't build a fresh DB client. Everything the agent does has to go
through its declared tools.

**How to ship this:**

- **MCP-only agent configuration.** Tools the agent can call are
  exhaustively listed in the MCP server manifest. No
  `bash` / `exec` / `shell` / `run_command` tool exposed.
  Specifically for SQL: expose a `sql_query` tool that opens its
  connection via `localhost:5433` (dbounce's listener) rather than
  exposing a raw `subprocess.run(["psql", ...])`.
- **Claude Code default config.** As of the current release, Claude
  Code does not give the agent a shell primitive by default; the user
  must opt in explicitly with `--dangerously-skip-permissions` or by
  approving each Bash invocation. Keep that default.
- **Cursor agent mode** without the "Run terminal commands"
  permission ticked.

**Tools that do NOT satisfy this layer out of the box:**

- Most LangChain ReAct agents bootstrapped with the standard
  `shell_tool` / `terminal_tool` — these expose `subprocess.run` to
  the LLM by design.
- Several open-source agent loops that ship with a shell tool as
  their primary capability (the "shell is the universal tool" school
  of thought). Treat any agent loop whose flagship example wires a
  shell tool as **not Layer-1 safe** without modification.

**What this layer does NOT cover:** an agent that asks the human to
paste a SQL statement into psql still wins — the prompt-injection
moves up a level into social engineering. Layers 2–6 cover the
residual risk.

### Layer 2 — Sandbox the agent

**Very strong.** Run the agent inside a Docker container, microVM,
Firecracker VM, or browser sandbox where the laptop's shell is not
reachable.

Key properties:

- **Connection-string env vars set immutably inside the sandbox.**
  The sandbox starts with
  `DATABASE_URL=postgres://app@host.docker.internal:5433/app` baked
  into the container's `ENV` (the host:port is dbounce's, not the
  real DB's). Even if the agent runs `unset DATABASE_URL` inside the
  sandbox, that only unsets it in the sandbox's shell; the
  psycopg2 / pg-client process inherits the original env from
  container `ENV`.
- **Sandbox network namespace only routes egress through dbounce's
  outbound IP.** The sandbox is on its own Docker network whose
  iptables rules block 5432 / 3306 / 1433 / 5439 directly and only
  allow the dbounce port (5433 by default).
- **Agent can `pkill` inside the sandbox.** dbounce is on the HOST,
  outside the sandbox; the agent's `pkill dbounce` finds no matching
  PID inside its container.

**Concrete: Docker run with a constrained connection string.**

```sh
# On the host, create a dedicated Docker network whose outbound
# rules block direct DB ports.
docker network create \
  --driver bridge \
  --subnet 172.32.0.0/24 \
  --opt com.docker.network.bridge.enable_ip_masquerade=false \
  bouncer-net

# iptables rules on the host: this network is blocked from talking
# directly to common DB ports; dbounce is the only escape hatch.
sudo iptables -I OUTPUT -s 172.32.0.0/24 -p tcp \
  -m multiport --dports 5432,3306,1433,5439,1521 \
  -j REJECT
sudo iptables -t nat -A PREROUTING -s 172.32.0.0/24 \
  -p tcp --dport 5433 -j DNAT --to-destination 127.0.0.1:5433

# Run the agent inside this network with the bounced connection
# string baked in.
docker run --rm -it \
  --network bouncer-net \
  -e DATABASE_URL=postgres://app@host.docker.internal:5433/app \
  -e PGHOST=host.docker.internal \
  -e PGPORT=5433 \
  my-agent:latest
```

The `app` user in the connection string is a database account whose
GRANT set is **the absolute ceiling.** dbounce narrows from there.
The agent CANNOT exceed the user's GRANTs even if it bypasses
dbounce — that is the Layer-1-equivalent for SQL (database-level
GRANTs on the role the sandbox holds).

### Layer 3 — Network egress allowlist

**Strong.** Block the dev-machine's direct egress to the database's
real host/port except via dbounce's outbound IP. This catches the
case where the agent (or a human under social engineering) tries to
open a fresh psycopg2 connection to `prod-rds.<account>.us-east-1.rds.amazonaws.com:5432`
directly.

**macOS — pf (packet filter):**

`/etc/pf.anchors/com.bouncer`:

```
# Allow loopback (dbounce listens on 127.0.0.1:5433)
pass quick on lo0

# Allow dbounce's own process (uid 501 is the operator account) to
# reach the upstream DB
pass out proto tcp from any to any port { 5432, 3306 } user 501 keep state

# Block every OTHER user process from reaching the database hosts
table <db_hosts> persist file "/etc/bouncer/db_hosts.txt"
block out quick proto tcp from any to <db_hosts> port { 5432, 3306, 1433, 5439, 1521 }
```

Load with:

```sh
sudo pfctl -a com.bouncer -f /etc/pf.anchors/com.bouncer
sudo pfctl -e
```

**Linux — nftables:**

```
table inet bouncer {
  chain output {
    type filter hook output priority 0; policy accept;

    # Allow loopback
    oifname "lo" accept

    # Allow dbounce's process (matched by cgroup or uid) to reach the
    # upstream DB
    meta skuid 1000 accept

    # Block everyone else from DB endpoints
    ip daddr @db_hosts tcp dport { 5432, 3306, 1433, 5439, 1521 } reject with tcp reset
  }

  set db_hosts {
    type ipv4_addr
    flags interval
    # Populate from /etc/bouncer/db_hosts.txt
  }
}
```

**Corporate / VPN exit:** push the same allowlist as a VPN egress
ACL. Every laptop's DB traffic must exit through a corporate proxy
whose upstream is dbounce.

**Cloud dev workspaces (Codespaces, Gitpod, etc.):** VPC route tables
+ a NAT instance running dbounce. Same shape. **Production
databases:** the database's own security group should already deny
direct connections from anything except dbounce's outbound IP — this
is the strongest version of Layer 3, and the one that holds even
when the laptop's pf rules don't.

### Layer 4 — MDM-enforced signed binary + managed env vars

**Strong for managed fleets.** Use Jamf / Kandji / Intune /
equivalent to lock down:

- **Which processes can run.** Only the signed `dbounce` binary, with
  a known SHA-256, can listen on the loopback port. Modified binaries
  refuse to launch.
- **Managed env vars that the user (or agent) cannot modify.**
  `DATABASE_URL`, `PGHOST`, `PGPORT`, `MYSQL_HOST` and similar are
  shipped as managed preferences and re-applied on every login.
  `unset DATABASE_URL` in a shell unsets it for that shell session,
  but the next-launched process inherits the managed value again.
- **Prevent `pkill` of managed services.** macOS Endpoint Security
  framework profiles can block signal-delivery to processes in a
  managed list.
- **Lock down `~/.pgpass` and `~/.my.cnf`.** The managed dbounce
  config lives at `/etc/dbounce/`; user-writable credential files
  that could bypass dbounce are removed by MDM policy or denied by
  file-system policy (AppArmor / SELinux / macOS TCC).

**macOS Configuration Profile** (illustrative `.mobileconfig` payload
keys — full XML omitted for brevity; consult Apple's `profiles`
reference):

```
PayloadType: com.apple.systempolicy.kernelextensionpolicy
  AllowedTeamIdentifiers: [ <dbounce-signing-team-id> ]

PayloadType: com.apple.ManagedClient.preferences
  ManagedPreferences:
    DATABASE_URL: "postgres://app@127.0.0.1:5433/app"
    PGHOST: "127.0.0.1"
    PGPORT: "5433"

PayloadType: com.apple.TCC.configuration-profile-policy
  Services.SystemPolicyAllFiles:
    - Identifier: <dbounce-bundle-id>
      Authorization: Allow
```

**Linux — systemd hardening:**

```
[Service]
ExecStart=/usr/local/bin/dbounce run --profile safe-default
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
NoNewPrivileges=true
ProtectKernelModules=true
ProtectKernelTunables=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
```

Combined with **AppArmor** (`/etc/apparmor.d/usr.local.bin.dbounce`):

```
/usr/local/bin/dbounce {
  capability net_bind_service,
  network inet stream,
  /home/*/.dbounce/state.db rwk,
  /home/*/.dbounce/state.db-journal rwk,
  /etc/bouncer/** r,
  /etc/dbounce/** r,
  deny /home/*/.ssh/** rwx,
  deny /home/*/.pgpass rwx,
  deny /home/*/.my.cnf rwx,
}
```

**Windows — Group Policy + WDAC (Windows Defender Application
Control):** ship a WDAC policy whose `Allowed Publishers` list
includes only the dbounce signing certificate; set the `DATABASE_URL`,
`PGHOST`, `PGPORT` environment variables via a Group Policy Preference
(Computer Configuration → Preferences → Environment) so they reapply
on every user-login refresh.

### Layer 5 — launchd / systemd KeepAlive watchdog

**Medium.** If the agent does manage to kill dbounce, the OS-level
process supervisor restarts it within seconds. Combined with Layer 6,
the security team sees both the kill event AND the restart event in
the audit stream — a strong signal for incident response.

**macOS launchd plist** —
`/Library/LaunchDaemons/com.bouncer.dbounce.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.bouncer.dbounce</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/dbounce</string>
    <string>run</string>
    <string>--dialect</string>
    <string>postgres</string>
    <string>--port</string>
    <string>5433</string>
    <string>--mgmt-port</string>
    <string>8768</string>
  </array>
  <key>KeepAlive</key>
  <true/>
  <key>RunAtLoad</key>
  <true/>
  <key>ThrottleInterval</key>
  <integer>5</integer>
  <key>StandardOutPath</key>
  <string>/var/log/dbounce.out.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/dbounce.err.log</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>HOME</key>
    <string>/Users/operator</string>
  </dict>
</dict>
</plist>
```

Install:

```sh
sudo cp com.bouncer.dbounce.plist /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/com.bouncer.dbounce.plist
```

**Linux systemd unit** — `/etc/systemd/system/dbounce.service`:

```ini
[Unit]
Description=dbounce — local SQL gating proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/dbounce run --dialect postgres --port 5433 --mgmt-port 8768
Restart=always
RestartSec=5
User=dbounce
Group=dbounce

# Hardening (see Layer 4)
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

Install:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now dbounce.service
```

Each restart emits a dbounce startup audit event (one row per process
start; see `dbounce audit tail --event startup`). Pair with Layer 6
so the SIEM sees the kill/restart cycle.

### Layer 6 — Heartbeat + admin-action audit (what dbounce ships)

**Detection, not prevention.** This is the layer dbounce itself
provides; the other five layers are customer-owned infrastructure.

What dbounce emits today:

- **HEARTBEAT** events every N seconds (default 30s) to the audit
  pipeline. Configurable via `DBOUNCE_HEARTBEAT_INTERVAL`.
- **Slice-2 alert rule `heartbeat_gap`** fires when the SIEM-side
  view of the audit stream sees a gap larger than 2× the configured
  interval. Routes to whichever sink the operator configures
  (Slack webhook, generic webhook, OCSF/Splunk HEC).
- **Admin-action OCSF events** for rule-mutation, profile-install,
  mode-change, and pause-override attempts. These are emitted even
  when the attempt fails the authorization check, so an agent trying
  to relax the rule set is visible.

**Cross-correlation signal:** the audit pipeline can correlate
dbounce events against the database's own audit log (pg_audit /
MySQL audit plugin / Snowflake QUERY_HISTORY / BigQuery audit logs).
Any DB-side audit row attributed to the operator's DB user for which
there is NO matching dbounce audit row in the same window = the
proxy was bypassed. That correlation is the canonical bypass
detector.

**What the operator must do:**

1. Route dbounce audit to a SIEM (Splunk, Sumo, Datadog,
   Elasticsearch, etc.) — see
   [docs/QUERYING-AUDIT-LOGS.md](QUERYING-AUDIT-LOGS.md).
2. Enable the `heartbeat_gap` alert rule on that SIEM.
3. Subscribe the security team to the alert channel.

---

## Worked example: combining layers 1 + 3 + 5 + 6

A common deployment for an engineer / analyst laptop running Claude
Code as the agent against a production analytics DB:

- **Layer 1 (partial):** Claude Code in its default config, with
  `Bash` tool approval prompts left on (don't
  `--dangerously-skip-permissions`).
- **Layer 3:** macOS pf rules blocking direct `5432` egress except
  for the dbounce process **and** the production DB security group
  permitting only dbounce's outbound IP (defense in depth at both
  ends).
- **Layer 5:** launchd plist with `KeepAlive: true` so any
  `pkill dbounce` triggers an automatic restart within ~5 seconds.
- **Layer 6:** dbounce HEARTBEAT events routed to Splunk via the
  audit-export pipeline + `heartbeat_gap` alert wired to the SecOps
  Slack channel.

**Combined behavior on a prompt-injection disable attempt:**

1. Injected prompt arrives via a poisoned tool response or a poisoned
   row in a result-set the agent is summarising.
2. Agent attempts `pkill dbounce` — Claude Code surfaces the Bash
   approval prompt; the user (hopefully) denies.
3. If the user approves (or the deployment skipped Layer 1), dbounce
   dies → launchd restarts it within ~5s.
4. During the gap, the agent attempts a direct
   `psql postgres://...@prod-rds...:5432/...` call — pf blocks the
   connection at the TCP layer locally; even if pf were down, the
   prod RDS security group rejects the connection.
5. `heartbeat_gap` alert fires in Splunk; security team is paged.
6. Audit chain shows the kill event, the restart event, and the
   blocked direct-egress attempt — full forensic picture.

The bypass attempt is **detected within seconds**, **can't reach the
database directly**, and **dbounce keeps coming back**. No single
layer provides this on its own; the combination does.

---

## What dbounce CAN'T do

Explicit, honest list of what is **not** in dbounce's lane:

- **We don't prevent the disable itself.** A user-process can be
  killed by the user. That's how operating systems work. dbounce can
  only make the kill visible.
- **We don't ship MDM.** Jamf, Kandji, Intune, and equivalent are the
  customer's IT-management tooling. dbounce can be packaged for
  managed deployment, but the policy enforcement is the MDM's.
- **We don't ship the sandbox.** Docker, Firecracker, gVisor, browser
  sandboxes — pick the one that fits your agent's runtime. dbounce
  runs on the host; the sandbox is the customer's container layer.
- **We don't ship the firewall rules.** pf, nftables, VPN ACLs, VPC
  route tables, RDS/Cloud-SQL security groups — these are
  network-team / DBA responsibilities. dbounce provides the loopback
  target; the routing decision is upstream.
- **We don't enforce file-system policy.** Whether the agent can
  read `~/.pgpass` directly (and then open a connection to the real
  DB using those credentials without going through the proxy) is an
  AppArmor / SELinux / macOS TCC concern. See Layer 4.
- **We don't replace database-side GRANTs.** The DB role the operator
  authenticates as is the absolute ceiling on what any query can
  ever do. dbounce + DB-side GRANTs compose well; the GRANT set
  should be **the most-narrow set that lets the operator do their
  job**, with dbounce adding session/statement-level gating on top.

**What dbounce ships:** the audit signal, the heartbeat, the alert
rule, the admin-action event stream, and this doc explaining how to
compose all six layers.

---

## FAQ

**Q: What stops a prompt-injected agent from running `pkill dbounce`
as its first command?**

**A:** Nothing in dbounce itself. The full answer is "Layer 1
prevents the agent from having a shell, Layer 5 restarts dbounce if
it does get killed, Layer 6 alerts the SecOps team within seconds,
and Layer 3 blocks the direct-DB attempt during the restart window."
That combination is what stops the attack — not any single layer.

This is the same shape as host-IDS or endpoint detection: a
prompt-injected agent can `rm -rf` a CrowdStrike agent's files too,
which is why CrowdStrike pairs detection with kernel-level
tamper-protection and a network-level egress block. dbounce uses the
same playbook, but the kernel-level tamper-protection is the
customer's MDM (Layer 4), not anything dbounce can ship as a
user-space binary.

**Q: Can dbounce be run as root to prevent the user (or agent) from
killing it?**

**A:** Running dbounce as root makes `pkill` require root, which
helps against an agent running as the unprivileged user — but it
introduces its own risks (a vulnerability in dbounce becomes a root
vulnerability) and it doesn't help against an agent that has sudo
(many dev-laptop setups give the engineer NOPASSWD sudo).

The Bounce-suite recommendation is: run dbounce as the engineer's
own user account, NOT as root. Use **Layer 5 (launchd / systemd
KeepAlive)** for the "always-restart-on-kill" property. Use
**Layer 4 (MDM-managed process protection)** for the "user can't
kill it at all" property — that one belongs to the OS, not dbounce.

If you have a hard requirement to run dbounce as a privileged
daemon, you can — `Restart=always` + `User=root` in the systemd
unit works — but the hardening team should review the resulting
threat model carefully. The default-recommended deployment is
user-process with launchd/systemd supervision.

---

## Related docs

- [`QUERYING-AUDIT-LOGS.md`](QUERYING-AUDIT-LOGS.md) — wiring audit
  output to a SIEM (the Layer 6 prerequisite).
- The cross-suite hardening doc is replicated in the `ibounce`,
  `kbounce`, and `gbounce` repos with their respective env-var and
  upstream-protocol specifics — the threat model and layer model are
  identical across the Bounce suite.
