# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024-2025 DeMoD LLC. All rights reserved.
#
# DCF Serialize - Multi-stage Dockerfile
# For environments without Nix (prefer `nix build .#docker` when available)

# =============================================================================
# Stage 1: Build environment
# =============================================================================
FROM alpine:3.19 AS builder

# Build dependencies
RUN apk add --no-cache \
    gcc \
    musl-dev \
    make \
    linux-headers

# Set build metadata
ARG VERSION=5.2.0
ENV DCF_VERSION=${VERSION}

WORKDIR /build

# Copy source files
COPY dcf_serialize.h dcf_serialize.c dcf_serialize_test.c Makefile ./
COPY LICENSE ./

# Build library and run tests
RUN make all test && \
    make install PREFIX=/usr DESTDIR=/install

# =============================================================================
# Stage 2: Runtime (minimal image)
# =============================================================================
FROM alpine:3.19 AS runtime

LABEL org.opencontainers.image.title="DCF Serialize"
LABEL org.opencontainers.image.description="DeMoD Communications Framework Serialization Shim"
LABEL org.opencontainers.image.version="5.2.0"
LABEL org.opencontainers.image.vendor="DeMoD LLC"
LABEL org.opencontainers.image.licenses="BSD-3-Clause"
LABEL org.opencontainers.image.source="https://github.com/demod-llc/dcf-serialize"

# Install runtime dependencies (none for pure C)
RUN apk add --no-cache libgcc

# Copy built artifacts from builder
COPY --from=builder /install/usr/lib/libdcf_serialize* /usr/lib/
COPY --from=builder /install/usr/include/dcf /usr/include/dcf
COPY --from=builder /install/usr/lib/pkgconfig /usr/lib/pkgconfig
COPY --from=builder /build/LICENSE /usr/share/licenses/dcf-serialize/

# Set library path
ENV LD_LIBRARY_PATH=/usr/lib

# Default command (library only, override in derived images)
CMD ["sh", "-c", "echo 'DCF Serialize library installed at /usr/lib. Use as base image for your application.'"]

# =============================================================================
# Stage 3: Development image (optional)
# =============================================================================
FROM alpine:3.19 AS development

LABEL org.opencontainers.image.title="DCF Serialize (dev)"
LABEL org.opencontainers.image.vendor="DeMoD LLC"

# Development dependencies
RUN apk add --no-cache \
    gcc \
    musl-dev \
    make \
    gdb \
    valgrind \
    linux-headers \
    git \
    bash

# Copy built artifacts
COPY --from=builder /install/usr/lib/libdcf_serialize* /usr/lib/
COPY --from=builder /install/usr/include/dcf /usr/include/dcf
COPY --from=builder /install/usr/lib/pkgconfig /usr/lib/pkgconfig

# Copy source for development
COPY --from=builder /build /src/dcf-serialize

WORKDIR /src/dcf-serialize

ENV LD_LIBRARY_PATH=/usr/lib
ENV PKG_CONFIG_PATH=/usr/lib/pkgconfig

CMD ["/bin/bash"]

# =============================================================================
# Stage 4: Test runner
# =============================================================================
FROM runtime AS test

COPY --from=builder /build/dcf_serialize_test /usr/bin/

ENTRYPOINT ["/usr/bin/dcf_serialize_test"]
