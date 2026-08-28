#!/bin/sh
# agentrec agent installer for Linux hosts (CI runners, VMs, bare metal).
#
#   curl -fsSL https://agentrec.io/install.sh | sudo sh -s -- --token ar_ing_xxx
#
# Downloads the agentrec binary for your architecture from GitHub Releases, verifies its
# checksum, and writes a config with your ingest token so `agentrec trace` auto-uploads.
# Needs root (eBPF requires privileges) and a Linux 5.8+ kernel with BTF.
set -eu

API_DEFAULT="https://api.agentrec.io"
REL_DEFAULT="https://github.com/adisingh925/agentrec/releases/latest/download"
ENDPOINT="$API_DEFAULT"; REL="$REL_DEFAULT"; TOKEN=""; BIN_URL=""; PREFIX="/usr/local/bin"

while [ $# -gt 0 ]; do
  case "$1" in
    --token)    TOKEN="$2"; shift 2;;
    --endpoint) ENDPOINT="$2"; shift 2;;
    --bin-url)  BIN_URL="$2"; shift 2;;
    --release)  REL="$2"; shift 2;;
    --prefix)   PREFIX="$2"; shift 2;;
    *) echo "unknown flag: $1" >&2; exit 2;;
  esac
done

[ "$(id -u)" = "0" ] || { echo "please run as root (eBPF needs privileges)"; exit 1; }
[ -n "$TOKEN" ] || { echo "--token is required (an ingest token, ar_ing_…)"; exit 1; }
[ "$(uname -s)" = "Linux" ] || { echo "agentrec runs on Linux only (got $(uname -s))"; exit 1; }
[ -r /sys/kernel/btf/vmlinux ] || echo "warning: /sys/kernel/btf/vmlinux missing — kernel may lack BTF (need 5.8+ CO-RE)"

case "$(uname -m)" in
  x86_64|amd64)  ARCH=amd64;;
  aarch64|arm64) ARCH=arm64;;
  *) echo "unsupported architecture: $(uname -m)"; exit 1;;
esac

BIN_URL="${BIN_URL:-$REL/agentrec-linux-$ARCH}"
TMP="$(mktemp)"
echo "downloading agentrec (linux-$ARCH) from $BIN_URL"
curl -fsSL "$BIN_URL" -o "$TMP"

# verify against the release checksums.txt (mandatory — fail closed on any doubt)
command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum not found — cannot verify download; aborting"; rm -f "$TMP"; exit 1; }
EXPECTED="$(curl -fsSL "$REL/checksums.txt" | awk -v f="agentrec-linux-$ARCH" '$2==f{print $1}')"
[ -n "$EXPECTED" ] || { echo "could not fetch checksum for agentrec-linux-$ARCH — aborting"; rm -f "$TMP"; exit 1; }
GOT="$(sha256sum "$TMP" | awk '{print $1}')"
[ "$GOT" = "$EXPECTED" ] || { echo "checksum mismatch — aborting"; rm -f "$TMP"; exit 1; }
echo "checksum verified"

install -m 0755 "$TMP" "$PREFIX/agentrec"; rm -f "$TMP"
mkdir -p /etc/agentrec
printf 'AGENTREC_ENDPOINT=%s\nAGENTREC_TOKEN=%s\n' "$ENDPOINT" "$TOKEN" > /etc/agentrec/agent.env
chmod 600 /etc/agentrec/agent.env

echo "installed: $("$PREFIX"/agentrec info 2>/dev/null | head -1 || echo agentrec)"
echo
echo "record + auto-upload a workload:"
echo "  set -a; . /etc/agentrec/agent.env; set +a"
echo "  agentrec trace -- <your-agent-command>"
