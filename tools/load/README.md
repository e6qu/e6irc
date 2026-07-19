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
`PREFIX{index}`), `--burst K` (default 10), `--tls`.

**Use `--channels` for realistic numbers.** One giant channel makes the
join phase O(N²) — each join sends a NAMES list of every current member
and is broadcast to all of them — which masks true throughput. A real
large deployment spreads users across many channels. Measured locally
(release, macOS, 2000 clients, burst 10):

| layout        | connect  | fan-out     | latency p50 |
|---------------|----------|-------------|-------------|
| 1 channel     | 290 c/s  | 59k msg/s   | 131 ms      |
| 200 channels  | 6042 c/s | 122k msg/s  | 37 ms       |

The residual latency at scale is the single core worker (the N=1 case of
the sharded design, DESIGN §7.3) serializing every channel's fan-out —
core sharding is the open scale-hardening item.

Output:

```
connect+register+join: 1000/1000 in 0.42s (2381 clients/s)
fan-out: 19980/19980 messages in 0.31s (64451 msg/s)
latency (µs): p50 4210.0  p90 8800.5  p99 12030.1  max 13990.2
```

`fan-out` counts `burst × (clients − 1)` deliveries (every non-sender
receives each burst message once). The latency line is true end-to-end
per delivery (sender stamps each message's send time; receivers subtract
it), so the tail reflects real queue time under burst, not a mean.

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
  server config govern memory under load; size them per the memory-budget
  work (still open in Phase 13) before a full 100k run.

Run `sweep.sh` to walk client counts and tabulate the results:

```
tools/load/sweep.sh 127.0.0.1:6667 "100 500 1000 5000 20000"
```

The full 100k run, fan-out/latency **targets**, timer wheels, and the
per-connection memory budget remain open Phase 13 items — this harness is
the instrument they will be measured with.
