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
CFLAGS      ?= -O2 -Wall -Wextra -Wpedantic
CFLAGS      += -fPIC -std=c11
LDFLAGS     ?=

# Debug build
ifdef DEBUG
  CFLAGS    += -g -O0 -DDEBUG -fsanitize=address,undefined
  LDFLAGS   += -fsanitize=address,undefined
endif

# Source files
SRCS        := dcf_serialize.c
HDRS        := dcf_serialize.h
TEST_SRCS   := dcf_serialize_test.c
OBJS        := $(SRCS:.c=.o)

# Output files
STATIC_LIB  := libdcf_serialize.a
SHARED_LIB  := libdcf_serialize.so.$(VERSION)
SHARED_LINK := libdcf_serialize.so
TEST_BIN    := dcf_serialize_test

# Docker settings
DOCKER_IMAGE := dcf-serialize
DOCKER_TAG   := $(VERSION)

.PHONY: all clean install uninstall test docker docker-load docker-push help

# Default target
all: $(STATIC_LIB) $(SHARED_LIB) $(TEST_BIN)

# Static library
$(STATIC_LIB): $(OBJS)
	$(AR) rcs $@ $^

# Shared library
$(SHARED_LIB): $(SRCS) $(HDRS)
	$(CC) -shared $(CFLAGS) $(SRCS) -o $@ $(LDFLAGS)
	ln -sf $(SHARED_LIB) $(SHARED_LINK)

# Object files
%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -c $< -o $@

# Test binary
$(TEST_BIN): $(TEST_SRCS) $(STATIC_LIB) $(HDRS)
	$(CC) $(CFLAGS) $(TEST_SRCS) -L. -ldcf_serialize -o $@ $(LDFLAGS)

# Run tests
test: $(TEST_BIN)
	@echo "╔═══════════════════════════════════════════════════╗"
	@echo "║  Running DCF Serialize Tests                      ║"
	@echo "╚═══════════════════════════════════════════════════╝"
	LD_LIBRARY_PATH=. ./$(TEST_BIN)

# Memory check with valgrind
memcheck: $(TEST_BIN)
	LD_LIBRARY_PATH=. valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./$(TEST_BIN)

# Static analysis
lint:
	cppcheck --enable=all --suppress=missingIncludeSystem $(SRCS) $(HDRS)
	@command -v clang-tidy >/dev/null && clang-tidy $(SRCS) -- $(CFLAGS) || true

# Format code
format:
	clang-format -i $(SRCS) $(HDRS) $(TEST_SRCS)

# Install
install: all
	install -d $(DESTDIR)$(INCLUDEDIR)
	install -d $(DESTDIR)$(LIBDIR)
	install -d $(DESTDIR)$(PKGCONFIGDIR)
	install -m 644 $(HDRS) $(DESTDIR)$(INCLUDEDIR)/
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
	rm -f $(OBJS) $(STATIC_LIB) $(SHARED_LIB) $(SHARED_LINK) $(TEST_BIN)
	rm -f *.gcov *.gcda *.gcno

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
	@echo "  all           - Build static/shared libraries and test binary (default)"
	@echo "  test          - Build and run tests"
	@echo "  memcheck      - Run tests under valgrind"
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
	@echo "  DEBUG=1       - Enable debug build with sanitizers"
