# Build and run environment for agentrec.
#
# vmlinux.h is generated from the build host's BTF, which BuildKit exposes at
# /sys/kernel/btf/vmlinux. The probe uses only tracepoints, so the resulting object stays
# portable across kernels regardless of which one produced the header.

FROM --platform=$BUILDPLATFORM golang:1.24-bookworm AS build
ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
        clang llvm libbpf-dev bpftool libelf-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h \
    && echo "vmlinux.h: $(wc -l < bpf/vmlinux.h) lines"

RUN go mod tidy
RUN go generate ./...
RUN CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -o /out/agentrec ./cmd/agentrec

# Distribution binaries: the eBPF object is arch-independent bytecode, and the Go userspace
# is statically linked (CGO off), so we cross-compile both from this one build.
RUN mkdir -p /dist \
 && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /dist/agentrec-linux-amd64 ./cmd/agentrec \
 && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /dist/agentrec-linux-arm64 ./cmd/agentrec \
 && ls -la /dist


# Export-only stage: `docker build --target dist --output type=local,dest=…` drops the
# cross-compiled binaries on the host without shipping the whole build image.
FROM scratch AS dist
COPY --from=build /dist/ /


# Minimal PRODUCTION image (this is what release.yml publishes and customers pull): just the
# static agent binary + TLS roots. The agent watches the host's processes via hostPID, so no
# language runtimes, tools, or demo assets belong here.
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/agentrec /usr/local/bin/agentrec
WORKDIR /work
ENTRYPOINT ["agentrec"]
CMD ["info"]


# DEMO image (NOT published) — the local `make demo` sandbox only. Adds the tools a stand-in
# agent runs plus deliberately-planted BAIT credentials so the recorder has something sensitive
# to touch. Must never be shipped to customers; keep it strictly after `runtime`.
FROM runtime AS demo

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl git python3 procps \
    && rm -rf /var/lib/apt/lists/*
COPY demo/ /demo/
RUN chmod +x /demo/*.sh
RUN mkdir -p /root/.aws /root/.ssh /work/project \
    && printf '[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n' > /root/.aws/credentials \
    && printf -- '-----BEGIN OPENSSH PRIVATE KEY-----\nnot-a-real-key\n-----END OPENSSH PRIVATE KEY-----\n' > /root/.ssh/id_rsa \
    && printf '//registry.npmjs.org/:_authToken=npm_EXAMPLETOKEN\n' > /root/.npmrc \
    && printf '{"name":"demo-project","version":"1.0.0","dependencies":{"lodash":"^4.17.21"}}\n' > /work/project/package.json \
    && printf 'stale log\n' > /work/project/tmp.log \
    && chmod 600 /root/.aws/credentials /root/.ssh/id_rsa /root/.npmrc

WORKDIR /work
ENTRYPOINT ["agentrec"]
CMD ["info"]
