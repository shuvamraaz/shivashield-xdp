#!/usr/bin/env bash
#
# gen_vmlinux.sh — Generate vmlinux.h from kernel BTF.
#
# This script is a helper for environments where `make vmlinux`
# doesn't have bpftool on PATH.  It searches common locations.
set -eo pipefail

OUTDIR="${1:-ebpf/headers}"
OUTFILE="$OUTDIR/vmlinux.h"

log() { printf '\033[36m[*]\033[0m %s\n' "$*"; }
die() { printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

# Check kernel BTF.
[ -r /sys/kernel/btf/vmlinux ] || die "/sys/kernel/btf/vmlinux not found — need CONFIG_DEBUG_INFO_BTF=y"

# Find bpftool.
BPFTOOL=""
for candidate in bpftool /usr/sbin/bpftool /usr/lib/linux-tools/*/bpftool; do
    if command -v "$candidate" >/dev/null 2>&1 || [ -x "$candidate" ]; then
        BPFTOOL="$candidate"
        break
    fi
done
[ -n "$BPFTOOL" ] || die "bpftool not found — install it with your package manager"

mkdir -p "$OUTDIR"
log "Generating vmlinux.h with $BPFTOOL..."
$BPFTOOL btf dump file /sys/kernel/btf/vmlinux format c > "$OUTFILE"
LINES="$(wc -l < "$OUTFILE")"
log "Done: $OUTFILE ($LINES lines)"
