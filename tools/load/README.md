# Load testing (`e6irc-load`)

The `e6irc-load` binary (`crates/e6irc-load`) opens many concurrent client
connections against a running `e6ircd`, measures connect+register+join
throughput, then measures channel fan-out — one client bursts messages
into a shared channel and every other client counts and times its
deliveries.

```
cargo build --release -p e6irc-load -p e6ircd
target/release/e6irc-load --addr 127.0.0.1:6667 --clients 1000 --burst 20
```

Flags: `--addr host:port` (default `127.0.0.1:6667`), `--clients N`
(default 100), `--channels C` (default 1 — spread clients across C
channels), `--channel PREFIX` (default `#load`; actual channel is
`PREFIX{index}`), `--burst K` (default 10), `--tls`,
`--minimum-connect-rate N`, `--minimum-fanout-rate N`, and
`--maximum-p99-ms N`. On the tuned Linux qualification host,
`--server-pid PID` additionally samples e6ircd's resident set from `/proc`;
`--maximum-server-rss-per-connection-bytes N` turns the incremental peak
(above the pre-run server baseline, divided by requested clients) into another
acceptance threshold. The optional thresholds turn the measurement into an
acceptance gate: missing exact deliveries or violating any supplied threshold
exits nonzero.

**Use `--channels` for realistic numbers.** One giant channel makes the
join phase O(N²) — each join sends a NAMES list of every current member
and is broadcast to all of them — which masks true throughput. A real
large deployment spreads users across many channels. Measured locally
(release, macOS, 2000 clients, burst 10):

| layout        | connect  | fan-out     | latency p50 |
|---------------|----------|-------------|-------------|
| 1 channel     | 290 c/s  | 59k msg/s   | 131 ms      |
| 200 channels  | 6042 c/s | 122k msg/s  | 37 ms       |

The residual latency at scale comes from the single core worker serializing
every channel's fan-out.

Output:

```
connect+register+join: 1000/1000 in 0.42s (2381 clients/s)
fan-out: 19980/19980 messages in 0.31s (64451 msg/s)
latency (µs): p50 4210.0  p90 8800.5  p99 12030.1  max 13990.2
```

`fan-out` verifies the exact sequence set for all
`burst × (clients − channels)` deliveries (every non-sender receives its
channel sender's burst once). A same-sender post-burst marker fences every
delivery in wire order; a duplicate, missing,
out-of-range, or malformed sequence fails the run. The latency line is true end-to-end
per delivery (sender stamps each message's send time; receivers subtract
it), so the tail reflects real queue time under burst, not a mean.
Any failed client, timeout, socket error, or missing delivery makes the harness
exit nonzero; printed partial measurements can therefore never be mistaken for
a successful qualification.

`--report-json PATH` writes the versioned result contract: requested load,
measured rates and latency, server RSS, thresholds, and pass/fail state.
The harness rejects workloads above 100,000 clients or 10 million tracked
messages before it allocates tasks or measurement buffers.

## Toward the 100k-connection target (DESIGN §7.3, §17)

One box, one `e6ircd`, ~100k concurrent sessions is the design target.
The harness and the server both need OS headroom well above defaults:

- **File descriptors** — each connection is one fd on each side. Raise the
  soft limit for both processes: `ulimit -n 262144` (and a matching
  `LimitNOFILE` if running `e6ircd` under systemd).
- **Ephemeral ports** — a single-host loopback test consumes a client port
  per connection; 100k exceeds the default range. Widen it
  (`net.ipv4.ip_local_port_range = 1024 65535` on Linux) and/or drive the
  server from several client hosts. macOS caps loopback throughput hard —
  use Linux for high counts.
- **Backlog & buffers** — raise `net.core.somaxconn` and the listen backlog;
  watch `net.ipv4.tcp_mem` / socket buffer pressure.
- **Server sizing** — `core_queue`, `sendq`, and `max_hot_channels` in the
  server config govern memory under load. Queue bounds allocate lazily, so an
  empty per-connection SendQ does not reserve its maximum 1,024 envelopes.
  Pass the server process ID and a host-specific
  `--maximum-server-rss-per-connection-bytes` value to enforce the chosen
  incremental resident-memory budget.

Run `sweep.sh` to walk client counts and tabulate the results:

```
tools/load/sweep.sh 127.0.0.1:6667 "100 500 1000 5000 20000" 20 \
  --report-dir results --minimum-connect-rate 100 --minimum-fanout-rate 1000 --maximum-p99-ms 500
```

Arguments after the burst are passed to every `e6irc-load` invocation, so one
sweep can enforce thresholds chosen for that controlled host. `--report-dir`
must name a new directory; it creates one JSON result per client count.

## Controlled Linux qualification

`qualify-linux.sh` runs one explicit-budget campaign and writes `result.json`
and `host.txt`. It rejects a non-e6ircd PID, insufficient file-descriptor
limits, ephemeral-port capacity, or listen backlog before it starts. It is a
single-load-host tool; its client count cannot exceed that host's ephemeral
port range. Its output directory must not exist, so it cannot overwrite prior
evidence. `--report-json` also refuses an existing file.

```
tools/load/qualify-linux.sh 127.0.0.1:6667 "$SERVER_PID" 20000 200 20 results/20000 \
  100 1000 500 262144
```

The final four values are minimum connect rate, minimum fan-out rate, maximum
P99 milliseconds, and maximum incremental server resident bytes per requested
connection. Keep the result and host files together when publishing a claim.

CI runs 64 clients across eight channels with a four-message burst against a
real debug daemon, requiring exact fan-out, at least 10 connections/second,
at least 100 deliveries/second, P99 below five seconds, and graceful shutdown.
On Linux it also samples the daemon and rejects more than 1 MiB of incremental
peak RSS per requested connection. Those deliberately generous shared-runner
limits catch catastrophic regressions without pretending to be a
production-host baseline. A tuned-host run supplies its own stricter RSS,
fan-out, and latency budgets. This harness is the measurement instrument, not
proof that the target has been met; see `docs/journeys/coverage.md`.
