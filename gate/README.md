# gate/ -- the Exsecutor admission gate

`dcf_serialize.c` is the reader. It is strict by default and **memory-safe on
its own**: every bounds check, depth limit and count check is plain C and does
not depend on anything in this directory. `gate/` adds a second, independent
opinion on whether a received frame is acceptable -- the same policy written a
second time in [Exsecutor](https://github.com/ALH477/exsecutor), a language whose
trap-free subset can be checked -- and the reader admits a frame only if **both**
say yes. Two implementations of one grammar, compared frame by frame, is the
point.

| file | what it is |
|---|---|
| `dcfs_gate.gen.c`, `dcfs_gate.gen.h` | **generated** by `exsc --emitte c` / `--emitte h`; never edited. `PROVENANCE.md` has the compiler, source, commands and hashes; `scripts/check-gate-fresh.sh` (`make check-gate`) re-verifies them |
| `dcfs_gate_unit.c` | includes the generated C unmodified, renaming its one import `exsrt_abortus` to `dcfs_gate_trap` and hiding its symbols |
| `dcfs_gate_host.c`, `dcfs_gate_host.h` | marshalling and the trap guard; `dcfs_gate_judge(frame, len, &verdict)` |
| `dcfs_gate_diff_test.c` | C validator versus gate on 358,132 frames |
| `dcfs_gate_guard_test.c` | the trap guard: contained, thread-local, fail-stop with no guard |
| `dcfs_gate_bench.c` | `make bench`: what the gate costs |
| `PROVENANCE.md` | where the generated files came from; **licence status: pending owner decision** |

`-DDCF_SER_NO_GATE` (or `make GATE=0`) compiles it all out. `DCF_SER_POLICY_NO_GATE`
skips it for one reader at run time.

## What the gate is asked, and when

`dcf_ser_reader_validate()` runs the C checks first. Only if all of them accept
does it ask the gate, once, about the whole frame (`dcfs_gate_judge`):

- frame up to **65557** bytes (17 header + 65536 payload + 4 CRC): copied into a
  zero-padded buffer of that size and judged by `exs_admitte_corpus` -- header
  policy, CRC-32 and the whole payload grammar;
- a larger frame (up to 16 MiB + 21): only `exs_admitte_caput` runs, on the first
  17 bytes and the length. The fixed-buffer ABI of the generated C has no slice
  type, so the payload is not copied; the C validator alone judges it.

The gate encodes the **fully strict** policy. It is therefore consulted only when
the reader asks for nothing beyond that: not when `NO_GATE`, `ALLOW_NO_CRC`,
`ALLOW_NONCANONICAL_VARINT`, `ALLOW_INVALID_UTF8`, `ALLOW_UNSTRUCTURED`,
`ALLOW_APP_FLAGS` or `ALLOW_LEGACY_CRC` is set (it would refuse exactly what those
flags exist to admit). `ALLOW_TRAILING` leaves it on: the bytes after the frame are
cut off before the gate sees the frame. `LAX_SCHEMA` is not a frame property.

If C accepts and the gate refuses -- or the gate traps -- the two implementations
disagree: the frame is **refused with `DCF_SER_ERR_INTERNAL`** and
`dcf_ser_gate_disagreements()` is incremented. (If C refuses, the gate is not asked.)
That a disagreement is a bug in one of the two is the whole reason to have both.

## The grammar

The contract both sides were written from. Big-endian throughout.

```
frame   := header payload crc
header  := magic(4) version(2) msg_type(2) flags(1) payload_len(4) sequence(4)          -- 17 bytes
           magic = 0x44434653 ("DCFS"); version: major (first byte) = 5, minor free
           flags: only STREAMING 0x04, FINAL 0x08, PRIORITY 0x10 (strict policy)
           payload_len <= 16777216 (DCF_SER_MAX_MESSAGE)
frame is exactly 17 + payload_len + 4 bytes
crc     := CRC-32 of header payload (IEEE 802.3 reflected, poly 0xEDB88320, init and xorout 0xFFFFFFFF)
payload := value*                          -- consumes exactly payload_len bytes
value   := tag body
  0x00 NULL                                no body
  0x01 BOOL  0x02 U8  0x03 I8              1 byte
  0x04 U16   0x05 I16                      2 bytes
  0x06 U32   0x07 I32  0x0A F32            4 bytes
  0x08 U64   0x09 I64  0x0B F64  0x30 TIMESTAMP  0x31 DURATION     8 bytes
  0x13 UUID                                16 bytes
  0x10 VARINT   LEB128, 1..10 bytes; 10th byte 0 or 1; >= 2 bytes never ends in 0x00
  0x11 STRING   u32 len <= 65536, len bytes of UTF-8 (RFC 3629; NUL allowed)
  0x12 BYTES    u32 len, len bytes
  0x20 ARRAY    elem_type u8, u32 count <= 1048576 and <= payload bytes left, then count values
  0x21 MAP      key_type u8, val_type u8, u32 count <= 1048576 and 2*count <= payload bytes left,
                then 2*count values
  0x22 STRUCT   u16 type_id, fields until the end marker; field = u16 id, u8 type, value;
                end marker = id 0 with type 0
  any other tag: refused
containers nest at most 32 deep (DCF_SER_MAX_DEPTH)
```

The C reference is `walk_values()` in `dcf_serialize.c`, iterative with an explicit
32-entry stack, shared by `dcf_ser_validate_payload()` and `dcf_ser_reader_skip()`.
The gate is `examples/dcfs_gate/dcfs_gate.exsc` in the Exsecutor tree; its README
carries the same grammar and the gate's verdict table. A third statement of it, in
Python (`examples/dcfs_gate/proba.py`), is the oracle that tests the gate.

## What was checked

All of this was run on x86_64 Linux, gcc 13 and clang 18.

- **Differential, C against gate** (`make test`, `gate/dcfs_gate_diff_test.c`):
  358,132 frames of up to 65557 bytes -- structured families (every `flags` value,
  every header byte perturbed, nesting 0..40 for each container, count and length
  boundaries, UTF-8 tables, varint shapes, every prefix of a frame) plus 250,000
  mutated random frames with length and CRC repaired or not -- **0 disagreements**;
  76 larger frames checked one way (what C accepts the header-only gate accepts),
  0 violations. Every gate verdict except 7 is reached (7, "longer than the
  gate's capacity", is only produced by a direct call). Five more seeds of
  1,500,000 random cases each (`dcfs_gate_diff_test 1500000 <seed>`, about 1.9 M
  frames per seed, 9.6 M in all): 0 disagreements. It found one real bug on its
  first run: the C library's CRC-32 table had a mistyped entry (`README.md`,
  "Security changes").
- **The gate against its own oracle** (in the Exsecutor tree, `proba_c.sh`):
  281,314 cases, exact verdicts, 5 builds, 26 mutants caught; plus one run of
  `proba.py --cases 800000 --seed 99` (1,138,203 cases): 0 disagreements.
- **The differential catches mutants of the gate**: 11 of 12 mutants of the
  Exsecutor source were noticed (the 12th, a string cap moved from 65536 to 65537,
  is equivalent when only admit/refuse is compared; the oracle compares exact
  verdicts and catches it).
- **Trap containment** (`gate/dcfs_gate_guard_test.c`): a deliberate trap inside a
  guarded call returns to the caller for every kind 0..9; eight threads x 20,000
  rounds of (trap, admit, refuse) never saw each other's guard; a trap with no guard
  active abort()s. Separately, a mutant of the gate that really does read past its
  buffer (string-body bound removed), fed a frame that claims a 64 KiB string, was run
  through `dcfs_gate_judge`: it returned `DCFS_GATE_TRAP` and the process lived. And a
  mutant that refuses every frame, run through `dcf_ser_reader_validate`, gave
  `DCF_SER_ERR_INTERNAL`, `dcf_ser_gate_disagreements() == 1`, and with
  `DCF_SER_POLICY_NO_GATE` gave `DCF_SER_OK`. (Those two mutant runs were done in a
  scratch directory, not committed: building a mutated gate is not part of the repo.)
- **Fuzzing**, `make fuzz` (entry point `dcf_serialize_fuzz.c`): the deterministic mutation
  fuzzer under gcc ASan+UBSan ran 150 s, 34,652,160 inputs (9.8 M frames validated and
  consumed, 8.6 M writer programs round-tripped), no crash, sanitizer report or property
  violation; libFuzzer (nixpkgs clang 21.1.8 with ASan+UBSan, coverage-guided) ran 131 s,
  2,974,391 executions, 889 coverage points, no finding. Injected bugs in the library
  (an unchecked fixed-size advance, a writer that finishes after a failed write, a
  struct-header bounds check removed, a writer that accepts invalid UTF-8) were each found
  by the mutation fuzzer within 30 s; a nesting limit moved from 32 to 33 was *not* (the
  fuzzer does not build 33-deep input; the hostile suite and the differential do catch it).
  `valgrind` over all test programs (`make memcheck`): 0 errors in every process.

### Is `examples/abortus/tutela.c` thread-safe?

Answer: yes by construction, and measured. `tutela.c` keeps its guard chain
(`summa`) and depth counter (`profunditas`) in `_Thread_local` variables, so a trap on
thread A can only jump to a `setjmp` made by thread A; and
`examples/abortus/proba_c.sh` was run here and passes (25/25 checks per build under
gcc and clang at -O0/-O2 and ASan, including eight threads x 100,000 rounds of
traps). This repository does **not** link `tutela.c`: it carries its own guard
(`dcfs_gate_host.c`, same idea, `_Thread_local` pointer to the active `jmp_buf`) so
the library has no dependency on the Exsecutor tree, and tests it with threads
itself.

### Cost

`make bench`, one machine, one run (these figures are for re-measuring, not quoting):
the gate alone runs at roughly 90-115 MB/s (its CRC-32 is bit by bit: the language has
no module-level table), the C validator at roughly 290-490 MB/s. A maximum-size frame
costs about 0.7 ms in the gate and 0.2 ms in C. A reader that cannot afford the
gate on every frame sets `DCF_SER_POLICY_NO_GATE`; the C checks are complete without it.

## What was not checked

- `[UNTESTED]` 32-bit targets and Windows (the gate is compiled out on Windows).
- `[OPEN]` The two implementations share an author and a reading of the grammar:
  agreement finds slips in either, not a misreading they share.
- `[UNTESTED]` The `Dockerfile` (no docker in the sandbox) and `nix flake check` of
  `flake.nix` as a whole (its inputs live on github.com, which the sandbox cannot
  reach). The flake's derivation was extracted verbatim and built with `nix build
  --impure --expr` against the registry's nixpkgs: it builds and its checkPhase (all
  four test programs and the hash check) passes.
- Licence: see `PROVENANCE.md`.
