# AGENTS.md

Working conventions for any agent (human or LLM) in this repository.
`CLAUDE.md` is a symlink to this file — there is one source of truth.

The full engineering laws live in `DESIGN.md` §2 (no silent no-ops, no
silent fallbacks, provenance required, make bug classes unrepresentable,
a paragraph justifying a line means the code is wrong). Read them. This
file adds the rule that governs *scope*.

Unsure what a term means? `docs/terminology.md` is the project glossary —
and the convention it sets is binding here: prefer the spelled-out term,
and do not introduce a new abbreviation without defining it there.

---

## The Boy-Scout Rule — HARD RULE

> **Leave the code cleaner than you found it. If you see something
> broken, fix it — even if it looks unrelated to your task.**

This is not advisory. It is not "when convenient." It is a hard rule.

### Everything is related

There is no such thing as an "unrelated" problem in this codebase. It is
one system — one process, one binary, one set of invariants. A broken
test in a crate you didn't touch, a stale comment pointing at a moved
file, a dead code path, a flaky container, a lint you silenced instead of
solved — every one of these is part of the same whole you are working in.

The *only* reason a defect can look unrelated is that an LLM's context
window cannot hold the entire system at once. That is a limitation of the
observer, **not a property of the code**. Do not mistake "I can't
currently see the connection" for "there is no connection." When you
notice brokenness, the connection is already proven: you are here, it is
here, therefore it is in scope.

### What this obligates you to do

- **Fix it, don't route around it.** If you discover a bug while doing
  something else, fixing it *is* part of the task. Don't file it for
  later, don't add a `// TODO`, don't narrow your PR to avoid it.
- **Fix the class, not just the instance** (DESIGN §2). While you're in
  there, ask what *kind* of bug this is and whether the design can make
  it impossible. Leaving the campground cleaner means the same litter
  can't blow back in.
- **Leave the tree green.** Every commit builds, every test passes, every
  clippy config is clean, `cargo-deny` is happy. "Cleaner" is not a
  vibe; it is a measurable state you restore before you stop.
- **Repair what you disturb.** If your change moves a file, update every
  reference to it (paths in CI, docs, comments) in the same change. Half
  a rename is new litter.
- **Surface, don't swallow.** If something is broken in a way you should
  *not* silently fix (it contradicts how it was described, it's not yours
  to change, it needs a decision), say so loudly — that too is leaving
  the campground better than the silent alternative.

### What it does NOT mean

- It is not license to balloon a change into a rewrite. Fix the
  brokenness; don't gold-plate the working. The bar is "cleaner," not
  "rebuilt to my taste."
- It is not license to leave the tree red mid-refactor. If a genuine fix
  is too large to land green in this pass, that is the rare case to
  surface and scope explicitly — never to commit broken.

### Why it's stated so strongly here

Agents lose the thread across context windows and rationalize narrow
scope: "that failing thing is unrelated to my task, skip it." In a system
where everything is related, that rationalization is always wrong. This
rule exists to override it every time.

---

## The No-Deferral Rule — HARD RULE

> **When you find a defect or a worthwhile fix, address it in the same
> change — or STOP and put the decision to the human. You may not
> unilaterally file it away to be done "later".**

Deferral is the failure mode this rule exists to kill. It has shown up as
"surfaced, not done", "deferred to a dedicated pass", "noted for a future
sweep", "gold-plating the working", a `// TODO`, or an entry in `BUGS.md`.
Every one of those is the same move: deciding *not to fix something now*
and hiding that decision in prose so it reads as settled. **That decision
is the human's to make, not the agent's.**

### The only three outcomes for something you find

1. **Fix it in this change.** The default. If it is worth writing down, it
   is worth fixing — writing it down instead is the deferral.
2. **Escalate it as an explicit question to the human** — loudly, in the
   response, phrased as a decision ("X exists; I can fix it by Y at cost
   Z, or leave it because W — which?"). Not a paragraph in `PLAN.md`; a
   question the human answers before the sweep is called done.
3. **Genuinely does not belong** (it contradicts a documented, tested
   design decision, or is out of the repo's scope). Then say so *to the
   human*, with the reason and the doc reference — and let them confirm.
   "It contradicts a design decision" is a claim to be checked, not a
   licence to file it yourself.

There is no fourth outcome. "Record it for later" is not an outcome; it is
the bug.

### This is not a licence to balloon or to grovel

The Boy-Scout rule's limits still hold: don't rewrite the working to your
taste, don't leave the tree red mid-refactor. A fix that is genuinely too
large to land green in one pass is exactly the case for outcome (2) — a
scoped question to the human — never outcome-zero, the silent file-away.
The point is not "do every refactor ever imagined." The point is that the
*choice* to not do one is surfaced as a decision, not buried.

### Why it's stated so strongly here

Because it already regressed. Sweep after sweep, with an explicit "do not
defer" instruction standing, the agent kept coining "surfaced, not done"
sections and moving on — treating "surface, don't swallow" as permission
to swallow-by-documenting. `tools/check-no-defer.sh` now fails the gate on
the known vehicles (an open `BUGS.md` entry, a new deferral idiom added to
`PLAN.md`), so the regression is caught mechanically and not left to
memory.

---

## Practical checklist before you stop

- [ ] Builds green (default **and** every feature: `embed-web`, `matrix`).
- [ ] `cargo test --workspace` passes; PG/feature-gated suites run where
      the environment allows.
- [ ] `cargo clippy --workspace --all-targets` clean in each feature
      config; `cargo fmt --all --check` clean.
- [ ] `cargo deny check` clean.
- [ ] `tools/check-noops.sh` clean (no deferred-work markers or unmessaged
      panics in shipped source).
- [ ] `tools/check-dead-code.sh` clean (no code kept alive only by tests —
      it builds the shipped artifacts with `cfg(test)` off).
- [ ] `tools/check-dead-pub.sh` clean (no fully-`pub` item referenced only by
      an integration test — the cross-crate case the compiler can't see).
- [ ] `tools/check-duplication.sh` clean (copy-paste under the ratchet; the
      fix is to extract shared logic, never to raise the threshold).
- [ ] `tools/check-no-defer.sh` clean (no deferral vehicle in use — see the
      No-Deferral Rule above: `BUGS.md` empty, no new "surfaced, not
      done"-style note in `PLAN.md`).
- [ ] Anything you moved/renamed: all references updated.
- [ ] Anything broken you noticed on the way: **fixed**, or escalated to the
      human as an explicit decision — never filed away for later.
- [ ] `DESIGN.md` / `PLAN.md` updated in the same change when behavior or
      status changed.
