# Reproducible Linux build/test environment for the kernel and policy CI
# jobs (same package set as the GitHub ubuntu-22.04 runners).
#
#   docker build -t fortress-ci ci/
#   docker run --rm -v "$PWD":/src -w /src fortress-ci ci/qemu-test.sh
#
# Base pinned by digest (ubuntu:22.04 as of 2026-09-12). Bump deliberately:
#   docker buildx imagetools inspect ubuntu:22.04
FROM ubuntu:22.04@sha256:829f6df217bcbae2b371026e81711d1a787c61b2967ad09d015063663ebafbf7

COPY packages.txt /tmp/packages.txt
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive xargs -a /tmp/packages.txt \
    apt-get install -y --no-install-recommends \
 && rm -rf /var/lib/apt/lists/*
