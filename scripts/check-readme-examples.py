#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024-2025 DeMoD LLC. All rights reserved.
#
# Extract the five example programs from README.md and build each of them with
# -Wall -Wextra -Werror, in the compiler's default mode and with -std=c11 -D_GNU_SOURCE, then link them
# against libdcf_serialize.a (run `make libdcf_serialize.a` first; `make check-readme` does).
#   usage: check-readme-examples.py [CC]
import os
import re
import subprocess
import sys
import tempfile

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
cc = sys.argv[1] if len(sys.argv) > 1 else "gcc"
text = open(os.path.join(root, "README.md"), encoding="utf-8").read()
want = {"dcf_capture_relay.c": ["-lpthread"], "dcf_receiver.c": [], "dcf_udp_sender.c": [],
        "dcf_udp_receiver.c": [], "dcf_mirror.c": ["-lpthread"]}
found = {}
for block in re.findall(r"```c\n(.*?)```", text, re.S):
    m = re.match(r"/\*\*\n \* (dcf_\w+\.c)", block)
    if m and m.group(1) in want:
        found[m.group(1)] = block
missing = sorted(set(want) - set(found))
if missing:
    print("FAIL: README.md has no block for", missing)
    sys.exit(2)

bad = 0
with tempfile.TemporaryDirectory() as tmp:
    for name, libs in want.items():
        path = os.path.join(tmp, name)
        open(path, "w", encoding="utf-8").write(found[name])
        for mode in ([], ["-std=c11", "-D_GNU_SOURCE"]):
            r = subprocess.run([cc] + mode + ["-Wall", "-Wextra", "-Werror", "-I" + root, "-fsyntax-only", path],
                               capture_output=True, text=True)
            ok = r.returncode == 0
            print("  [%s] %-20s %s" % ("ok" if ok else "FAIL", name, " ".join(mode) or "(default mode)"))
            if not ok:
                print(r.stderr[:600])
                bad += 1
        r = subprocess.run([cc, "-Wall", "-Wextra", "-Werror", "-I" + root, path,
                            os.path.join(root, "libdcf_serialize.a"), "-o", path + ".bin"] + libs,
                           capture_output=True, text=True)
        print("  [%s] %-20s links" % ("ok" if r.returncode == 0 else "FAIL", name))
        if r.returncode != 0:
            print(r.stderr[:600])
            bad += 1
sys.exit(1 if bad else 0)
