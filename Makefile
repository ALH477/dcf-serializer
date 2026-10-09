# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024-2025 DeMoD LLC. All rights reserved.
#
# DCF Serialize - Makefile
# Standalone build for non-Nix environments

# Configuration
VERSION     := 5.2.0
PREFIX      ?= /usr/local
LIBDIR      ?= $(PREFIX)/lib
INCLUDEDIR  ?= $(PREFIX)/include/dcf
PKGCONFIGDIR?= $(LIBDIR)/pkgconfig

# Compiler settings
CC          ?= gcc
AR          ?= ar
CFLAGS      ?= -O2
LDFLAGS     ?=

# Warnings are part of the build, whatever CFLAGS the caller passes.
WARN_FLAGS  := -Wall -Wextra -Wpedantic -Wformat=2 -Wformat-security -Wconversion \
               -Wsign-conversion -Wshadow -Wstrict-prototypes
override CFLAGS += -fPIC -std=c11 $(WARN_FLAGS)

# Hardening (HARDEN=0 to switch off). Each flag is probed, so a compiler or
# target that lacks one (-fcf-protection is x86-only) simply skips it.
HARDEN      ?= 1
cc-option    = $(shell printf 'int main(void){return 0;}\n' | $(CC) $(1) -x c - -o /dev/null 2>/dev/null && echo $(1))
HARDEN_CFLAGS  :=
HARDEN_LDFLAGS :=
ifeq ($(HARDEN),1)
  HARDEN_CFLAGS  += $(call cc-option,-fstack-protector-strong)
  HARDEN_CFLAGS  += $(call cc-option,-fstack-clash-protection)
  HARDEN_CFLAGS  += $(call cc-option,-fcf-protection)
  ifneq ($(shell uname -s),Darwin)
    HARDEN_LDFLAGS += -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
  endif
  ifndef DEBUG
    HARDEN_CFLAGS += -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
  endif
endif
override CFLAGS  += $(HARDEN_CFLAGS)
override LDFLAGS += $(HARDEN_LDFLAGS)

# Debug build: sanitizers, and a sanitizer report FAILS the run.
SAN_FLAGS   := -fsanitize=address,undefined -fno-sanitize-recover=all
ifdef DEBUG
  override CFLAGS  += -g -O0 -DDEBUG $(SAN_FLAGS)
  override LDFLAGS += $(SAN_FLAGS)
endif

# The Exsecutor admission gate (gate/). GATE=0 compiles it out (-DDCF_SER_NO_GATE):
# the C validator alone then decides, exactly as before the gate existed.
GATE        ?= 1
ifeq ($(GATE),0)
  override CFLAGS += -DDCF_SER_NO_GATE
endif

# Source files
SRCS        := dcf_serialize.c
GATE_SRCS   := gate/dcfs_gate_unit.c gate/dcfs_gate_host.c
ifneq ($(GATE),0)
  SRCS      += $(GATE_SRCS)
endif
HDRS        := dcf_serialize.h gate/dcfs_gate_host.h
TEST_SRCS   := dcf_serialize_test.c
HOSTILE_SRCS:= dcf_serialize_hostile_test.c
DIFF_SRCS   := gate/dcfs_gate_diff_test.c
GUARD_SRCS  := gate/dcfs_gate_guard_test.c
FUZZ_SRCS   := dcf_serialize_fuzz.c
OBJS        := $(SRCS:.c=.o)

# Output files
STATIC_LIB  := libdcf_serialize.a
SHARED_LIB  := libdcf_serialize.so.$(VERSION)
SHARED_LINK := libdcf_serialize.so
TEST_BIN    := dcf_serialize_test
HOSTILE_BIN := dcf_serialize_hostile_test
DIFF_BIN    := dcfs_gate_diff_test
GUARD_BIN   := dcfs_gate_guard_test
FUZZ_BIN    := dcf_serialize_fuzz
TEST_BINS   := $(TEST_BIN) $(HOSTILE_BIN)
ifneq ($(GATE),0)
  TEST_BINS += $(DIFF_BIN) $(GUARD_BIN)
endif

# Docker settings
DOCKER_IMAGE := dcf-serialize
DOCKER_TAG   := $(VERSION)

.PHONY: all clean install uninstall test interop bench memcheck fuzz check-gate docker docker-load docker-push help

# Default target
all: $(STATIC_LIB) $(SHARED_LIB) $(TEST_BINS)

# Static library
$(STATIC_LIB): $(OBJS)
	$(AR) rcs $@ $^

# Shared library
$(SHARED_LIB): $(OBJS)
	$(CC) -shared $(OBJS) -o $@ $(LDFLAGS)
	ln -sf $(SHARED_LIB) $(SHARED_LINK)

# Object files
%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -c $< -o $@

# The Exsecutor-emitted gate is GNU C11 and is not ours to warn about: it is
# compiled as its own unit (gate/dcfs_gate_unit.c), without the project warnings.
GATE_UNIT_CFLAGS = $(filter-out $(WARN_FLAGS) -std=c11,$(CFLAGS)) -std=gnu11 -w
gate/dcfs_gate_unit.o: gate/dcfs_gate_unit.c gate/dcfs_gate.gen.c gate/dcfs_gate.gen.h
	$(CC) $(GATE_UNIT_CFLAGS) -c $< -o $@

gate/dcfs_gate_host.o: gate/dcfs_gate_host.c gate/dcfs_gate.gen.h $(HDRS)
	$(CC) $(CFLAGS) -c $< -o $@

# Test binaries (linked against the library built above)
$(TEST_BIN): $(TEST_SRCS) $(STATIC_LIB) $(HDRS)
	$(CC) $(CFLAGS) $(TEST_SRCS) -L. -ldcf_serialize -o $@ $(LDFLAGS)

# Hostile-input regression suite (one forked child per test)
$(HOSTILE_BIN): $(HOSTILE_SRCS) $(STATIC_LIB) $(HDRS)
	$(CC) $(CFLAGS) $(HOSTILE_SRCS) -L. -ldcf_serialize -o $@ $(LDFLAGS)

# Differential test: C validator vs the Exsecutor gate
$(DIFF_BIN): $(DIFF_SRCS) $(STATIC_LIB) $(HDRS)
	$(CC) $(CFLAGS) $(DIFF_SRCS) -L. -ldcf_serialize -o $@ $(LDFLAGS)

# Guard test: linked against the static library (the trap hook is hidden in the shared one)
$(GUARD_BIN): $(GUARD_SRCS) $(STATIC_LIB) $(HDRS)
	$(CC) $(CFLAGS) $(GUARD_SRCS) $(STATIC_LIB) -pthread -o $@ $(LDFLAGS)

# Run tests
test: $(TEST_BINS)
	@echo "╔═══════════════════════════════════════════════════╗"
	@echo "║  Running DCF Serialize Tests                      ║"
	@echo "╚═══════════════════════════════════════════════════╝"
	LD_LIBRARY_PATH=. ./$(TEST_BIN)
	LD_LIBRARY_PATH=. ./$(HOSTILE_BIN)
ifneq ($(GATE),0)
	LD_LIBRARY_PATH=. ./$(DIFF_BIN)
	./$(GUARD_BIN)
endif
	@if command -v python3 >/dev/null 2>&1; then $(MAKE) --no-print-directory interop; else echo "[skip] interop: python3 not found"; fi

# The writer's ZigZag / LEB128 / CRC-32 against an independent decoder (Python, zlib) and the
# standard ZigZag vectors. Needs python3.
interop: $(STATIC_LIB) $(HDRS) scripts/varsint_emit.c scripts/varsint_interop.py
	$(CC) $(CFLAGS) scripts/varsint_emit.c $(STATIC_LIB) -o varsint_emit $(LDFLAGS)
	./varsint_emit | python3 scripts/varsint_interop.py
	@rm -f varsint_emit

# Cost of the gate next to the C validator (one machine, one run: re-measure, do not quote)
bench: $(STATIC_LIB) $(HDRS) gate/dcfs_gate_bench.c
	$(CC) $(CFLAGS) gate/dcfs_gate_bench.c $(STATIC_LIB) -o dcfs_gate_bench $(LDFLAGS)
	./dcfs_gate_bench
	@rm -f dcfs_gate_bench

# Memory check with valgrind (the hostile suite forks one child per test)
memcheck: $(TEST_BINS)
	LD_LIBRARY_PATH=. valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --error-exitcode=9 ./$(TEST_BIN)
	LD_LIBRARY_PATH=. valgrind --trace-children=yes --track-origins=yes --error-exitcode=9 ./$(HOSTILE_BIN)
ifneq ($(GATE),0)
	LD_LIBRARY_PATH=. valgrind --track-origins=yes --error-exitcode=9 ./$(DIFF_BIN) 20000
	valgrind --track-origins=yes --error-exitcode=9 ./$(GUARD_BIN)
endif

# Fuzzing. With clang and its libFuzzer runtime installed:
#     make fuzz CC=clang FUZZ_ENGINE=libfuzzer
# builds a libFuzzer target and runs it for FUZZ_SECONDS. Otherwise (and by
# default) it builds a deterministic mutation fuzzer under ASan+UBSan and runs it
# for FUZZ_SECONDS. Either way a finding is a crash or a sanitizer report.
FUZZ_SECONDS ?= 120
FUZZ_ENGINE  ?= mutation
FUZZ_SOURCES := $(FUZZ_SRCS) dcf_serialize.c $(if $(filter 0,$(GATE)),,$(GATE_SRCS))
FUZZ_FLAGS   := -std=gnu11 -O1 -g -fno-omit-frame-pointer $(SAN_FLAGS) -I. $(if $(filter 0,$(GATE)),-DDCF_SER_NO_GATE)
fuzz: $(FUZZ_SOURCES) $(HDRS)
ifeq ($(FUZZ_ENGINE),libfuzzer)
	$(CC) $(FUZZ_FLAGS) -fsanitize=fuzzer -DDCF_FUZZ_LIBFUZZER -w $(FUZZ_SOURCES) -o $(FUZZ_BIN)
	mkdir -p fuzz-corpus && ./$(FUZZ_BIN) -max_total_time=$(FUZZ_SECONDS) -max_len=70000 fuzz-corpus
else
	$(CC) $(FUZZ_FLAGS) -w $(FUZZ_SOURCES) -o $(FUZZ_BIN)
	ASAN_OPTIONS=detect_leaks=0 ./$(FUZZ_BIN) $(FUZZ_SECONDS)
endif

# Is the vendored gate what the Exsecutor compiler emits from the recorded source?
check-gate:
	./scripts/check-gate-fresh.sh

# Static analysis
lint:
	cppcheck --enable=all --suppress=missingIncludeSystem $(SRCS) $(HDRS)
	@command -v clang-tidy >/dev/null && clang-tidy $(SRCS) -- $(CFLAGS) || true

# Format code
format:
	clang-format -i dcf_serialize.c dcf_serialize.h $(TEST_SRCS) $(HOSTILE_SRCS)

# Install
install: all
	install -d $(DESTDIR)$(INCLUDEDIR)
	install -d $(DESTDIR)$(LIBDIR)
	install -d $(DESTDIR)$(PKGCONFIGDIR)
	install -m 644 dcf_serialize.h $(DESTDIR)$(INCLUDEDIR)/
	install -m 644 $(STATIC_LIB) $(DESTDIR)$(LIBDIR)/
	install -m 755 $(SHARED_LIB) $(DESTDIR)$(LIBDIR)/
	ln -sf $(SHARED_LIB) $(DESTDIR)$(LIBDIR)/$(SHARED_LINK)
	ln -sf $(SHARED_LIB) $(DESTDIR)$(LIBDIR)/libdcf_serialize.so.5
	@echo "prefix=$(PREFIX)" > $(DESTDIR)$(PKGCONFIGDIR)/dcf-serialize.pc
	@echo "exec_prefix=\$${prefix}" >> $(DESTDIR)$(PKGCONFIGDIR)/dcf-serialize.pc
	@echo "libdir=\$${exec_prefix}/lib" >> $(DESTDIR)$(PKGCONFIGDIR)/dcf-serialize.pc
	@echo "includedir=\$${prefix}/include" >> $(DESTDIR)$(PKGCONFIGDIR)/dcf-serialize.pc
	@echo "" >> $(DESTDIR)$(PKGCONFIGDIR)/dcf-serialize.pc
	@echo "Name: dcf-serialize" >> $(DESTDIR)$(PKGCONFIGDIR)/dcf-serialize.pc
	@echo "Description: DeMoD Communications Framework Serialization Shim" >> $(DESTDIR)$(PKGCONFIGDIR)/dcf-serialize.pc
	@echo "Version: $(VERSION)" >> $(DESTDIR)$(PKGCONFIGDIR)/dcf-serialize.pc
	@echo "Libs: -L\$${libdir} -ldcf_serialize" >> $(DESTDIR)$(PKGCONFIGDIR)/dcf-serialize.pc
	@echo "Cflags: -I\$${includedir}" >> $(DESTDIR)$(PKGCONFIGDIR)/dcf-serialize.pc

# Uninstall
uninstall:
	rm -f $(DESTDIR)$(INCLUDEDIR)/dcf_serialize.h
	rm -f $(DESTDIR)$(LIBDIR)/$(STATIC_LIB)
	rm -f $(DESTDIR)$(LIBDIR)/$(SHARED_LIB)
	rm -f $(DESTDIR)$(LIBDIR)/$(SHARED_LINK)
	rm -f $(DESTDIR)$(LIBDIR)/libdcf_serialize.so.5
	rm -f $(DESTDIR)$(PKGCONFIGDIR)/dcf-serialize.pc

# Clean
clean:
	rm -f dcf_serialize.o gate/*.o $(STATIC_LIB) $(SHARED_LIB) $(SHARED_LINK) $(TEST_BIN) $(HOSTILE_BIN) $(DIFF_BIN) $(GUARD_BIN) $(FUZZ_BIN)
	rm -f *.gcov *.gcda *.gcno
	rm -rf fuzz-corpus

# Build Docker image via Nix
docker:
	@echo "Building Docker image via Nix..."
	nix build .#docker
	@echo "Docker image built: ./result"
	@echo "Load with: docker load < ./result"

# Load Docker image
docker-load: docker
	docker load < ./result

# Build Docker image directly (non-Nix fallback)
docker-direct:
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) -f Dockerfile .
	docker tag $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_IMAGE):latest

# Help
help:
	@echo "DCF Serialize - Build Targets"
	@echo "=============================="
	@echo ""
	@echo "Build:"
	@echo "  all           - Build static/shared libraries and test binaries (default)"
	@echo "  test          - Build and run tests (unit, hostile-input, C-vs-gate differential)"
	@echo "  memcheck      - Run tests under valgrind"
	@echo "  fuzz          - Fuzz the reader and writer (FUZZ_SECONDS=120, FUZZ_ENGINE=mutation|libfuzzer)"
	@echo "  check-gate    - Re-emit the Exsecutor gate and compare with gate/ (skips without exsc)"
	@echo ""
	@echo "Install:"
	@echo "  install       - Install to PREFIX (default: /usr/local)"
	@echo "  uninstall     - Remove installed files"
	@echo ""
	@echo "Docker (via Nix):"
	@echo "  docker        - Build Docker image using Nix"
	@echo "  docker-load   - Build and load Docker image"
	@echo "  docker-direct - Build Docker image directly (Dockerfile)"
	@echo ""
	@echo "Development:"
	@echo "  lint          - Run static analysis"
	@echo "  format        - Format source code"
	@echo "  clean         - Remove build artifacts"
	@echo ""
	@echo "Variables:"
	@echo "  PREFIX=$(PREFIX)"
	@echo "  CC=$(CC)"
	@echo "  DEBUG=1       - Enable debug build with sanitizers (a report fails the run)"
	@echo "  GATE=0        - Compile the Exsecutor admission gate out (-DDCF_SER_NO_GATE)"
	@echo "  HARDEN=0      - Drop the hardening flags (stack protector, fortify, relro/now, ...)"
