#!/usr/bin/env bash
# scripts/check-gate-fresh.sh -- is the vendored Exsecutor gate what the compiler emits?
#
#   1. Always: the vendored files still have the sha256 recorded in gate/PROVENANCE.md
#      (nobody hand-edited a generated file).
#   2. When exsc and the Exsecutor source are available: re-emit with the exact commands
#      of PROVENANCE.md and `cmp` against the vendored files; also check the source's hash.
#      Otherwise print [skip] for this step.
#
# Where things are looked for:
#   EXSC       path to the exsc binary           (default: $EXSECUTOR/build/exsc)
#   EXSECUTOR  path to an Exsecutor checkout     (default: unset)
#   DCFS_GATE_SOURCE  path to dcfs_gate.exsc     (default: $EXSECUTOR/examples/dcfs_gate/dcfs_gate.exsc)
#
# Exit status: 0 fresh (or step 2 skipped), 1 stale or edited.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/.." && pwd)"
prov="$repo/gate/PROVENANCE.md"
fail=0

[ -f "$prov" ] || { echo "check-gate-fresh: $prov missing" >&2; exit 1; }

# ---- 1. hashes of the vendored files
sums="$(grep -E '^[0-9a-f]{64}  gate/' "$prov" || true)"
if [ -z "$sums" ]; then
  echo "  [FAIL] PROVENANCE.md records no hash for gate/ files"; exit 1
fi
if ( cd "$repo" && printf '%s\n' "$sums" | sha256sum -c --quiet - ); then
  echo "  [ok]   vendored files match the hashes in gate/PROVENANCE.md"
else
  echo "  [FAIL] a vendored file differs from the hash recorded in gate/PROVENANCE.md"; fail=1
fi

# ---- 2. re-emit
exsc="${EXSC:-}"
[ -n "$exsc" ] || { [ -n "${EXSECUTOR:-}" ] && exsc="$EXSECUTOR/build/exsc"; }
src="${DCFS_GATE_SOURCE:-}"
[ -n "$src" ] || { [ -n "${EXSECUTOR:-}" ] && src="$EXSECUTOR/examples/dcfs_gate/dcfs_gate.exsc"; }

if [ -z "${exsc:-}" ] || [ ! -x "$exsc" ] || [ -z "${src:-}" ] || [ ! -f "$src" ]; then
  echo "  [skip] re-emission: set EXSC and DCFS_GATE_SOURCE (or EXSECUTOR) to check the generated files against the compiler"
else
  want_src="$(grep -E '^[0-9a-f]{64}  source/' "$prov" | cut -d' ' -f1 || true)"
  have_src="$(sha256sum "$src" | cut -d' ' -f1)"
  if [ -n "$want_src" ] && [ "$want_src" != "$have_src" ]; then
    echo "  [FAIL] $src has sha256 $have_src, PROVENANCE.md records $want_src"; fail=1
  fi
  work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
  for k in c h; do
    if "$exsc" aedifica --hospes x86_64-linux --emitte "$k" "$src" -o "$work/gate.gen.$k" >/dev/null 2>&1; then
      if cmp -s "$work/gate.gen.$k" "$repo/gate/dcfs_gate.gen.$k"; then
        echo "  [ok]   exsc --emitte $k reproduces gate/dcfs_gate.gen.$k byte for byte"
      else
        echo "  [FAIL] exsc --emitte $k output differs from gate/dcfs_gate.gen.$k"; fail=1
      fi
    else
      echo "  [FAIL] exsc --emitte $k failed"; fail=1
    fi
  done
fi

[ "$fail" -eq 0 ] && echo "check-gate-fresh: ok" || { echo "check-gate-fresh: STALE"; exit 1; }
