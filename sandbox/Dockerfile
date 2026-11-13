# fuz-llm sandbox image (NFR-1, NFR-8)
#
# Isolation for all LLM-generated code and the untrusted target binary:
#   - no network at runtime (drop NET_ADMIN/NET_RAW, run with --cap-drop=ALL --network none)
#   - cgroup CPU/memory limits (enforced by the runtime, not here)
#   - non-root user
#
# Pinned base: Debian bookworm-slim (NFR-8). Bump deliberately; re-test the
# CEGIS loop after any base change.
FROM debian:bookworm-slim

# Pinned toolchain. clang ships libFuzzer + ASan + UBSan (FR-8, NFR-3).
# These are the versions available on bookworm; freeze via the ADR at M0.
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang-19=1:19.1.7-3~deb12u1 \
        lld-19=1:19.1.7-3~deb12u1 \
        libclang-rt-19-dev=1:19.1.7-3~deb12u1 \
        binutils \
        ca-certificates \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

# libFuzzer needs the compiler-rt fuzzing runtime.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libclang-common-19-dev=1:19.1.7-3~deb12u1 \
    && rm -rf /var/lib/apt/lists/*

# Default to clang-19 for builds inside the image.
ENV CC=clang-19 CXX=clang++-19

# Non-root execution user (NFR-1).
RUN useradd --create-home --shell /usr/sbin/nologin humpty
WORKDIR /work
USER humpty

# Entry point defaults to a shell; the orchestrator overrides the command.
CMD ["/bin/bash"]
