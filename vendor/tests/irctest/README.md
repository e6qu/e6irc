# irctest hookup

Glue for running the external **irctest** protocol-conformance suite
against e6ircd. The suite itself is **not** vendored into the tree; it is
cloned at a pinned commit by CI (and locally), and driven through the
controller here.

## Provenance

- **Source:** https://github.com/progval/irctest
- **Pinned commit:** `a468d9fcd64abc72b02ecb20f4f8612fd72c8829`
- **License:** the irctest suite is under its upstream license; it is run
  as a separate process against e6ircd and is not distributed with it.

## Files

- `e6ircd_controller.py` — an irctest controller that starts/stops
  e6ircd for each test (our glue, not upstream code).
- `run.sh` — convenience runner: clones irctest at the pinned commit,
  sets `PYTHONPATH` to this directory, and runs the green-list tests with
  the Solanum marker filter (`not implementation-specific and not
  deprecated and not strict and not services`).

CI runs the same green list; grow it as protocol surface lands.
