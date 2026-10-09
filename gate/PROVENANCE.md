# Provenance of the vendored Exsecutor gate

`gate/dcfs_gate.gen.c` and `gate/dcfs_gate.gen.h` are **generated files**. They
are the output of the Exsecutor compiler `exsc` on one `.exsc` source and are
checked in so that building `dcf-serializer` never needs `exsc` or `fasmg`.
Never edit them. `scripts/check-gate-fresh.sh` (`make check-gate`) proves they
are still what the recorded source produces.

| | |
|---|---|
| unit | `dcfs_gate` -- frame admission gate (`exs_admitte_caput`, `exs_admitte_corpus`) |
| source | `examples/dcfs_gate/dcfs_gate.exsc` in <https://github.com/ALH477/exsecutor>, branch `claude/festive-ride-da6s3q` |
| exsecutor commit (`git rev-parse HEAD` when emitted; contains the source) | `9319b262e0dc45c853a524a7a0f8d5f97cf3b6de` |
| compiler | `build/exsc` of that tree, sha256 `2196c34746c1fa1f68330bb84a3bdbd09f199024a86def3c967f3ddbf1931731` |
| date emitted | 2026-10-09 |
| host | x86_64 Linux (`--hospes x86_64-linux`) |

## Commands (exact)

```sh
exsc aedifica --hospes x86_64-linux --emitte c examples/dcfs_gate/dcfs_gate.exsc -o gate/dcfs_gate.gen.c
exsc aedifica --hospes x86_64-linux --emitte h examples/dcfs_gate/dcfs_gate.exsc -o gate/dcfs_gate.gen.h
```

`exsc` was run twice per output and the pairs compared byte-identical
(`examples/dcfs_gate/proba_c.sh` does this on every run). No `fasmg` is needed
for `--emitte c|h`; the emission above was also reproduced with a `PATH` that
contains no `fasmg`.

## Hashes

`scripts/check-gate-fresh.sh` verifies the three lines starting with a 64-digit hash.

```
17564c20dee9b92dfac1157b0cff5306cd92a4bee070f62c638242e862d31767  source/examples/dcfs_gate/dcfs_gate.exsc
63168141e56a4cc5f65dd1da305c048c801d3f7f6e42e8cefde30ad2412f9988  gate/dcfs_gate.gen.c
265294df2f72cf710c11fd1082f16c537b0524f43e55be78cee4d9f0ad0d40fe  gate/dcfs_gate.gen.h
```

(The first path is relative to the Exsecutor checkout, which is not part of this
repository.)

## How it is used here

- `gate/dcfs_gate_unit.c` `#include`s `dcfs_gate.gen.c` unmodified, after
  `#define exsrt_abortus dcfs_gate_trap` (the one symbol the emitted C imports and
  that must not return) and under hidden symbol visibility. It is compiled as GNU
  C11 without this project's warning flags -- the emitted C uses GNU extensions.
- `gate/dcfs_gate_host.c` supplies `dcfs_gate_trap` as a `_Thread_local` setjmp guard
  (a trap inside a guarded call returns to the caller instead of ending the process;
  with no guard active it `abort()`s) and the `dcfs_gate_judge()` marshalling.
- `-DDCF_SER_NO_GATE` (or `make GATE=0`) compiles the gate out; the C validator
  alone then decides. `DCF_SER_POLICY_NO_GATE` skips it per reader.

## Licence status

The `.exsc` source is **GPL-3.0-or-later**. Exsecutor's `LICENSE.EXCEPTION`
Exception A frees only the compiler's own contribution to the emitted C; it
does not relicense the source's content. A relicensing grant of the kind
`LICENSE.GRANTS` GRANT 1 gives the `custos` unit is needed before this emitted
file ships in a BSD-3-Clause repository such as this one.

**Status: pending owner decision.** Nothing here edits `LICENSE.GRANTS`.
Until the owner decides, treat `gate/dcfs_gate.gen.c` as GPL-3.0-or-later and
build with `GATE=0` / `-DDCF_SER_NO_GATE` where that is unacceptable; the C
validator is complete without it.
