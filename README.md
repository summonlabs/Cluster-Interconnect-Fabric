# Cluster Interconnect Fabric

**A cluster-wide communication-authority runtime.** CIF answers exactly one
question, and refuses to answer any other:

> Given member domains, topology, communication obligations, capacity, path
> authority, failures, maintenance state and current generations, *which
> cluster-wide communication relationships are authoritative now*, what resources
> back them, and when must they be degraded, fenced or refused?

CIF is a C++20 / CMake library, a daemon (`cifd`) and an inspection CLI
(`cif`). It has **no third-party dependencies** — the SHA-256 and CRC-32C
implementations, the canonical codec, the framed transport, the persistence
layer, the test harness and the benchmarks are all in this repository.

Copyright 2026 Summon Software Labs. Apache License 2.0.

---

## What CIF actually is

A **grant** is the only artifact in CIF that carries cluster-wide communication
authority. One grant binds, indivisibly:

| Binding                | Field                                                       |
| ---------------------- | ----------------------------------------------------------- |
| source scope           | member id + member generation + member digest + endpoint     |
| destination scope      | member id + member generation + member digest + endpoint     |
| topology               | path id + path generation                                    |
| capacity               | resource id + reservation generation + units                 |
| cluster coordinate     | cluster id, cluster generation, epoch, policy generation     |
| ruler                  | controller incarnation (a fresh 128-bit value per start)     |
| lifetime               | lease id, issue tick, expiry tick                            |
| exactly-once identity  | attempt id, bound to the exact request bytes                 |
| durability             | prepare sequence and commit sequence in the journal          |

Two principles run through the whole runtime:

1. **Eligibility is not authority.** Satisfying a communication contract makes a
   request *eligible*. Capacity, exclusivity, maintenance windows, failure
   domains, current generations and a durable commit are separately required
   before anything is granted.
2. **Acknowledgement is not verified effect.** An acknowledgement records that a
   caller *observed* a commit. It is stored separately from the commit that
   produced it, and it never implies that anything happened on a wire.

### The twelve outcomes are twelve different things

CIF keeps these distinct, and every decision carries the typed reason that
produced it:

| Outcome         | Means                                                                    |
| --------------- | ------------------------------------------------------------------------ |
| `GRANTED`       | Full requested scope authorised.                                          |
| `DEGRADED`      | Authorised with an explicitly recorded reduction.                         |
| `REFUSED`       | Policy, capacity or a constraint denies authority.                        |
| `FENCED`        | The artifact is fenced: a superseded epoch, incarnation or generation.    |
| `STALE`         | The caller's view of cluster state is older than the controller's.        |
| `CONFLICTING`   | A competing grant or attempt already holds the relationship.              |
| `INCOMPLETE`    | Required evidence was not supplied; the engine cannot tell.               |
| `INDETERMINATE` | Commit ambiguity: neither committed nor not-committed is provable.        |
| `UNKNOWN`       | The referenced entity was never seen by this controller.                  |
| `UNSUPPORTED`   | Outside the modelled domain — typically physical hardware behaviour.      |
| `CANCELLED`     | Cancelled by the client or an administrator.                              |
| `INVALID`       | Malformed request; nothing was evaluated and nothing was written.         |

---

## Boundaries — what CIF deliberately is not

These are hard boundaries, not a roadmap. CIF has no code for any of them and
makes no claim about any of them.

| Adjacent runtime                    | CIF's relationship                                                                                     |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------ |
| **Rack / pod governance**           | A member domain is *published to* CIF. CIF echoes the domain's member digest and generation verbatim and never invents, probes or re-derives a member. |
| **Generic planning / scheduling**   | Out of scope. CIF does not decide *what* should talk; it decides whether a stated relationship may.       |
| **Bandwidth brokering**             | Out of scope. CIF reserves declared units against declared pools; it does not police, shape or measure traffic. |
| **Optical control**                 | Out of scope, and named as unsupported at runtime.                                                       |
| **NIC / DPU offload**               | Out of scope, and named as unsupported at runtime.                                                       |
| **Workload placement**              | Out of scope.                                                                                            |
| **Inter-cluster connectivity**      | A separate runtime. A contract that requires an inter-cluster capability is answered `UNSUPPORTED` / `INTER_CLUSTER_UNSUPPORTED`. |
| **Physical transports** (RDMA, InfiniBand, RoCE, NVLink, NVSwitch, PCIe, switch ASICs) | **Not modelled and not claimed.** A contract requiring such a capability is answered `UNSUPPORTED` / `HARDWARE_SEMANTICS_UNSUPPORTED`. A path's `declared_hops` is caller metadata and is never authoritative. |

**REAL vs SYNTHETIC vs UNSUPPORTED.** Everything CIF measures and proves here is
real: real processes, real sockets, real files, real hard kills. The cluster
*descriptions* are synthetic in the tests (a generator declares members and
paths). Physical interconnect behaviour is UNSUPPORTED and is never simulated in
a way that could be mistaken for a measurement.

---

## Building

Requirements: CMake ≥ 3.25, a C++20 compiler, and nothing else.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

CMake options:

| Option                    | Default | Effect                                                            |
| ------------------------- | ------- | ----------------------------------------------------------------- |
| `CIF_BUILD_TESTS`         | ON      | Build the test suite.                                              |
| `CIF_BUILD_EXAMPLES`      | ON      | Build the examples.                                                |
| `CIF_BUILD_BENCHMARKS`    | ON      | Build the benchmarks.                                              |
| `CIF_WARNINGS_AS_ERRORS`  | ON      | MSVC `/W4 /WX`; GCC/Clang `-Wall -Wextra -Wpedantic -Wconversion -Werror`. |
| `CIF_ENABLE_SANITIZERS`   | OFF     | AddressSanitizer/UBSan (or MSVC `/fsanitize=address`).              |
| `CIF_ENABLE_TEST_HOOKS`   | OFF     | Compile test-only hooks into `cifd`.                                |

### Installing and consuming

```sh
cmake --install build --prefix /opt/cif
```

```cmake
find_package(CIF 1.0 REQUIRED)
target_link_libraries(my_app PRIVATE cif::core cif::net)
```

`tests/downstream/` is a complete, independent consumer: it knows nothing about
this source tree, builds against the installed prefix only, and runs as the
`cif.downstream.consumer` test.

---

## Using it

### Run a controller

```sh
cifd --cluster prod-a --port 7300 --journal /var/lib/cif/prod-a.cifjournal
```

`cifd` writes a ready file when it is listening, and stops cleanly when the file
named by `--stop-file` appears or when it is interrupted.

### Inspect and govern

```sh
cif --port 7300 query controller
cif --port 7300 query state
cif --port 7300 query recovery
cif --port 7300 query verify          # runs the engine's own invariant check
cif --port 7300 query member m-a
cif --port 7300 query grant g-1

cif --port 7300 admin upsert-member ... # see 'cif --help' for the full set
cif --port 7300 admin fence-all --detail "site partition"
cif --port 7300 admin advance-tick --tick 1000

cif --port 7300 submit --contract c-1 --source m-a --dest m-b --units 8 --attempt att-1
cif --port 7300 resolve --attempt att-1
cif --port 7300 release --grant g-1 --lease l-1
cif --port 7300 ack  --grant g-1 --lease l-1
cif --port 7300 cancel --attempt att-1 --reason withdrawn

cif journal scan   --path /var/lib/cif/prod-a.cifjournal
cif journal replay --path /var/lib/cif/prod-a.cifjournal
cif digest         --path /var/lib/cif/prod-a.cifjournal
```

`cif` speaks the same wire protocol as any other client. Nothing it can do is
something a client cannot do, and nothing it can do bypasses authority.

### Embed it

```cpp
#include <cif/authority.hpp>

cif::AuthorityCore core;
core.initialize(cif::ClusterId::from_validated("prod-a"),
                cif::ControllerIncarnation::generate(),
                cif::PolicyGeneration{1}, cif::Tick{1}, nullptr);

cif::AuthorityDecision decision = core.submit(request);
if (decision.outcome == cif::AuthorityOutcome::Granted) {
  // decision.grant binds source, destination, path, capacity, epoch and lease.
}
```

Three runnable examples are in `examples/`: `cif_example_authority` walks the
authority model, `cif_example_durability` closes and reopens a real journal, and
`cif_example_parallel_clients` hosts a daemon and points competing clients at it.

---

## Durability and recovery

The journal is a versioned, integrity-checked, bounded transition log:

- every record carries a format version, a length, a payload CRC-32C and a
  **chain** CRC that binds it to its predecessor, so removal, reordering and
  splicing are detectable rather than merely unlikely;
- a torn record ends the scan; the surviving prefix is adopted and the exact
  number of discarded bytes is reported;
- the log is bounded by byte count and record count, and compaction replaces it
  with a single snapshot atomically;
- a record is written and synced **before** the state it describes takes effect
  in memory. A crash can therefore only lose work that was never authorised.

**Recovered state is historical, never fresh.** A restart advances the epoch and
binds a new incarnation, so every artifact from before the restart is visibly
older. Recovery then applies a stated policy:

| Recovered artifact                                    | What happens                                                                 |
| ----------------------------------------------------- | ---------------------------------------------------------------------------- |
| prepare record, no commit                             | Provably **not** authorised: the grant is released, its capacity returned, and the attempt resolves to `REFUSED / COMMIT_NOT_DURABLE`. |
| durable commit, no acknowledgement                     | Genuinely **ambiguous**: the grant is **quarantined**. Its capacity is held so it can never be handed out twice, it carries no usable authority, and every resolve answers `INDETERMINATE / COMMIT_AMBIGUOUS` with `requires_reconciliation`. The caller resolves it by acknowledging (which re-validates and lifts the quarantine) or cancelling (which returns the capacity). |
| acknowledged commit                                    | Re-validated against the recovered specification and, if still sound, re-issued under the new epoch. If any member generation, digest, path generation or capacity moved, it is revoked and its capacity returned. |
| grant with a superseded epoch/incarnation              | Fenced.                                                                       |
| anyone else's journal, a corrupt prefix, a bad version  | Refused, with the reason reported.                                            |

Exactly-once semantics are explicit: **an attempt id is exactly-once for a
specific request**. Submitting byte-identical content returns the recorded
answer; the same attempt id with different content is `CONFLICTING`; a fresh
evaluation needs a fresh attempt id. Reconciliation of an existing attempt goes
through `resolve`, which is deliberately **not** fenced by epoch or
incarnation — that is what makes a restart recoverable in one round trip.

---

## Concurrency and ownership

The design is small enough to state completely.

- Exactly **one reducer thread** owns the `AuthorityCore`. Nothing else touches
  it, so the engine needs no internal locking and its invariants are checkable by
  reading one file.
- The reducer performs **no I/O**. It turns a decoded request into a decoded
  reply and deposits the reply in the requesting connection's mailbox. Socket
  backpressure therefore cannot stall authority.
- One worker thread per connection performs all socket I/O for that connection.
- The ingress queue is bounded, and a full queue is reported to the producer as
  backpressure. Producers never block on the reducer.
- **Lock order: there isn't one, by construction.** The ingress-queue mutex and a
  connection mailbox mutex are both leaf locks, and no thread ever holds two at
  once. Workers are joined only after every lock has been released.
- A connection owns its worker `std::thread`, so connections are moved out of
  the table one at a time and joined before destruction — compacting the table
  with `remove_if` would destroy a connection whose thread is still joinable,
  which is `std::terminate`.

Embedding processes that want to govern a running daemon without opening a
socket use `AuthorityServer::apply()` and `inspect()`, which go through the very
same reducer.

---

## Bounds

Every bounded quantity lives in `include/cif/limits.hpp` and is validated
*before* allocation. Counts decoded from untrusted bytes are compared against
those constants before any container is resized, and every arithmetic operation
on untrusted quantities goes through the checked helpers in `include/cif/bytes.hpp`.

| Bound                       | Value   |
| --------------------------- | ------- |
| identifiers, notes          | 128 B, 512 B |
| members / paths / contracts | 4096 / 16384 / 4096 |
| grants / attempts           | 65536 / 65536 |
| journal record / journal    | 1 MiB / 64 MiB |
| frame / frame payload       | 1 MiB / 1 MiB − 64 B |
| connections / ingress queue | 128 / 8192 |

---

## Testing

The suite is 95 individual tests, exposed as one CTest entry per binary plus
granular entries for the highest-value tests, plus a downstream-consumer entry
that installs the package, builds an independent project against it, and runs it.
Running `ctest` outside a developer environment reports the consumer entry as
**skipped with the reason**, never as a pass.

| Binary                 | What it covers                                                                 |
| ---------------------- | ------------------------------------------------------------------------------ |
| `cif_test_core`        | identities, SHA-256 (NIST vectors), CRC-32C, canonical codec, UTF-8, seeded RNG, journal round-trip, torn tail, bit-flip corruption, replay/reorder, compaction |
| `cif_test_authority`   | grants, every one of the twelve outcomes, fencing, member replacement, capacity closure, resource reservations, commit-before-acknowledge, renewals, maintenance windows, lifecycle transitions, locality, obligations, recovery |
| `cif_test_property`    | a seeded differential test against an independently written reference model, plus capacity, accounting-closure, idempotency and determinism invariants over randomised operation sequences |
| `cif_test_adversarial` | frame bombs, header/trailer tampering, per-byte mutation of every encoded frame, truncation at every length, oversized counts, invalid Unicode, extreme values, duplicate and regressing identities, journal truncation at every byte, spliced records, and 4000 random byte-mutation trials |
| `cif_test_net`         | every message type round-trips, hostile framing over a real socket, byte-at-a-time reassembly, connection limits, repeated start/stop, concurrent competing grants, parallel accounting closure, durable reopen |
| `cif_test_process`     | **independent OS processes**: `cifd` spawned, hard-killed with `TerminateProcess`, restarted against the same journal; this binary re-executes itself in a child mode that hard-kills at a *precise* durability boundary (after prepare, after commit, after the attempt record, after acknowledgement), proved by exit code |

**There are no timeouts, no watchdogs, and no "forced termination counts as a
pass" anywhere in this tree.** A hang is a defect to diagnose.

The multiprocess tests prove commit-before-acknowledge handling by killing a
process at the exact instant a specific record has been written and synced — not
by inferring a boundary from timing.

---

## Measured behaviour

All figures below are from a Release build on the machine that produced this
repository (Windows 11, MSVC 19.44, 16 logical cores). They are measurements, not
estimates, and they say nothing about any physical fabric.

`cif_bench_authority` — decisions against a declared cluster, with the engine's
own invariants checked after every completed phase:

| Members | Paths | Declare cluster | Decisions | Decisions/s |
| ------- | ----- | --------------- | --------- | ----------- |
| 64      | 256   | 0.5 ms          | 20 000    | 1 333       |
| 512     | 2048  | 17 ms           | 20 000    | 890         |
| 2048    | 8192  | 73 ms           | 20 000    | 904         |

`cif_bench_transport` — loopback TCP through the real frame codec and the real
daemon:

| Workload                        | Result                    |
| ------------------------------- | ------------------------- |
| Sequential ping round trips     | 35.3 µs each (28 313/s)   |
| Decisions over the wire         | 107 µs each (9 327/s)     |
| Parallel pings, 8 connections   | 125 313/s                 |

### The one cost that matters, measured

The **digest of the whole authoritative state** is, by construction, a pure
function of that state: producing it costs O(live grants + attempts). Every
decision carries it by default, which is what makes "which state was this answer
against?" answerable rather than a matter of trust. That is not free, and the
benchmark measures exactly how much:

| Members | Paths | Live grants | With state digest | Without |
| ------- | ----- | ----------- | ----------------- | ------- |
| 64      | 256   | 1 000       | 4 862/s           | 135 224/s |
| 512     | 2048  | 1 000       | 4 851/s           | 129 738/s |
| 2048    | 8192  | 1 000       | 4 833/s           | 120 492/s |

A 28× difference is a real trade-off, so it is a switch rather than a hidden
default: `AuthorityOptions::decision_state_digest = false`. With it off,
decisions remain fully deterministic — outcome, reasons, the grant and every
coordinate are still covered by the decision digest — and the full-state digest
remains available on demand through a `State` query. It stays **on** by default
because for an authority service, "which state was this answer against?" is worth
more than throughput.

Two fixes took the worst of this cost out and are worth naming: the specification
digest is now cached against the spec revision (it previously re-encoded every
member and path on every call, which alone cost 2.35 ms per decision at 2 048
members / 8 192 paths), and the state digest is composed from cached component
digests instead of re-encoding the specification.

---

## Limitations

Stated plainly, because a runtime that hides its edges is not trustworthy.

- **Loopback TCP only, IPv4 only.** The transport has been exercised over
  `127.0.0.1`. No multi-host deployment has been performed, and none is claimed.
- **No hardware.** No CUDA, RDMA, InfiniBand, RoCE, NVLink, NVSwitch, PCIe,
  optical, switch or vendor-SDK behaviour is modelled, integrated or claimed.
- **No real fabric measurements.** Every capacity figure in this repository is a
  caller-declared number. CIF reserves declared units; it does not observe
  traffic.
- **No quorum, no consensus, no replication.** One controller rules one cluster.
  A `--recovery fence-all` policy exists for the case where an operator cannot
  tolerate any continuity assumption across a restart, but CIF does not elect
  leaders.
- **Single-writer journal.** One process writes a given journal at a time; there
  is no multi-writer coordination.
- **POSIX is implemented but unproven here.** The platform layer has a full
  POSIX path (`fsync`, `fork`+`execv`, `SIGKILL`, `select`), but this work was
  built and proven on Windows with MSVC. GCC/Clang and Linux have not been
  exercised and are not claimed.
- **Sanitizer coverage is AddressSanitizer only, and only where the toolchain
  supports it.** Where it does not, this document says so rather than claiming
  otherwise.
- **The audit trail is diagnostic and is not persisted.** A recovered controller
  reports its audit history as empty rather than replaying remembered decisions
  as if they had just happened.

---

## Repository layout

```
include/cif/     public API (installed)
src/             implementation
apps/            cifd (daemon) and cif (CLI)
tests/           the six test binaries, the harness, and the downstream consumer
examples/        three runnable examples
benchmarks/      two completed-work benchmarks
```

## Contributing

See `CONTRIBUTING.md`. Contributions are accepted under the Apache License 2.0
with a Developer Certificate of Origin sign-off. There is no CLA and no
copyright assignment.

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
