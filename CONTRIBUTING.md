# Contributing to Cluster Interconnect Fabric

Copyright 2026 Summon Software Labs.

Thank you for considering a contribution. This document states the terms under
which contributions are accepted.

## License of contributions

By submitting a contribution to this project you agree that your contribution is
licensed under the **Apache License, Version 2.0**, the same license that covers
the project. You keep the copyright to your contribution.

There is **no Contributor License Agreement (CLA)** and no copyright assignment.
You do not sign anything, and you do not transfer ownership of your work. The
inbound license simply matches the outbound license, which is what makes the
project's licensing unambiguous for everyone who uses it.

If you are contributing on behalf of an employer, make sure you have permission
to do so under those terms.

## Developer Certificate of Origin

Every commit must carry a `Signed-off-by` line certifying the Developer
Certificate of Origin 1.1:

```
Signed-off-by: Your Name <your.email@example.com>
```

Use `git commit -s` to add it automatically. The certificate is:

> By making a contribution to this project, I certify that:
>
> (a) The contribution was created in whole or in part by me and I have the
>     right to submit it under the open source license indicated in the file; or
>
> (b) The contribution is based upon previous work that, to the best of my
>     knowledge, is covered under an appropriate open source license and I have
>     the right under that license to submit that work with modifications,
>     whether created in whole or in part by me, under the same open source
>     license (unless I am permitted to submit under a different license), as
>     indicated in the file; or
>
> (c) The contribution was provided directly to me by some other person who
>     certified (a), (b) or (c) and I have not modified it.
>
> (d) I understand and agree that this project and the contribution are public
>     and that a record of the contribution (including all personal information
>     I submit with it, including my sign-off) is maintained indefinitely and
>     may be redistributed consistent with this project or the open source
>     license(s) involved.

## What a change has to clear

1. **Build warning-clean in Release and Debug.** MSVC is built with `/W4 /WX`;
   GCC and Clang with `-Wall -Wextra -Wpedantic -Wconversion -Werror`. The
   project does not carry warning suppressions for its own code.
2. **The full test suite passes.** `ctest` from a configured build directory.
   There are no timeouts and no watchdogs: a hanging test is a defect to
   diagnose, not something to bound away.
3. **New behaviour is covered by a test that would fail without it.** Property
   tests must derive every random value from the harness seed and must print the
   seed on failure.
4. **Claims match evidence.** If a change asserts something about a platform,
   a protocol or a piece of hardware, the proof must be in the tree. CIF is
   explicit about the difference between REAL, SYNTHETIC and UNSUPPORTED.
5. **No new dependencies** without a prior discussion in an issue. The project's
   zero-dependency property is a feature, not an accident.

## Boundaries this project keeps

CIF governs cluster-wide communication authority. It deliberately does **not**
implement, model or claim:

- rack/pod governance (a member domain is published *to* CIF, not by it);
- generic planning or scheduling;
- bandwidth brokering;
- optical circuit control;
- NIC/DPU offload, RDMA, InfiniBand, NVLink or any other physical transport;
- workload placement;
- inter-cluster connectivity.

A pull request that adds hardware behaviour without a real device and real
measurements behind it will be declined, and a pull request that *claims* such
behaviour will be declined faster.

## Style

- C++20, no compiler extensions.
- Strongly typed identities and generations; no bare integers at an API
  boundary.
- Every decoder is total: bounds-checked, allocation-free until a size has been
  validated, and typed on failure. UNKNOWN, UNSUPPORTED, STALE, CONFLICTING,
  INCOMPLETE, INDETERMINATE, REFUSED, CANCELLED and INVALID stay distinct.
- Comments explain *why*, and are expected where a reader would otherwise have
  to reconstruct a concurrency or durability argument. The threading and
  durability contracts in `include/cif/server.hpp`, `include/cif/journal.hpp`
  and `include/cif/authority.hpp` are the reference for how that is written.
- Formatting follows the surrounding code: two-space indent, 100-column soft
  limit, `snake_case` for functions and variables, `PascalCase` for types.

## Reporting a defect

Please include: what you ran, what you expected, what happened, and — for
anything involving state that survives a restart — the journal file, its size,
and whether the process was killed or exited cleanly. The
`cif journal scan` and `cif digest` commands exist to make that easy to produce.
