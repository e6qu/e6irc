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
- `run.sh` — runner: `run.sh <irctest checkout at the pinned commit>
  <python with its requirements>`. It sets `PYTHONPATH` to this directory
  and runs the green-list tests with the Solanum marker filter (`not
  implementation-specific and not deprecated and not strict and not
  services`); arguments after the two replace the green list.
- `check_skips.py` — holds a run's skipped tests to a committed list.
  irctest skips, rather than fails, a test whose capability the server does
  not advertise, so a capability that stopped being advertised would leave
  the job green. Every skip must be listed under its reason, and a listed
  test that runs again must come off the list. `test_check_skips.py` is its
  contract.
- `expected-skips.txt` — the green list's skips (`run.sh` checks them).
- `expected-skips-services.txt` — the skips of CI's persistence-backed job
  (`irctest-services`).

CI runs the same green list; grow it as protocol surface lands.
