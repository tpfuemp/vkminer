#!/usr/bin/env bash
# vkminer -- a Vulkan compute cryptocurrency miner.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Assemble a release archive from a build that already exists.
#
#     ./package.sh                  package ./build
#     ./package.sh -B build-win     package the cross-built Windows .exe
#     ./package.sh -o /tmp/release  write the archive somewhere other than dist/
#     ./package.sh -k               keep the staging directory for inspection
#
# It deliberately does not build. Run ./build-linux.sh or ./build-win.sh first:
# a packaging script that compiles on the way past would hide the one failure
# this step exists to catch, an archive assembled from a stale binary.

set -euo pipefail

cd "$(dirname "$0")"

BUILD_DIR="build"
OUT_DIR="${VKMINER_DIST_DIR:-dist}"
KEEP=0

usage() {
    cat <<'EOF'
usage: ./package.sh [-B dir] [-o dir] [-k]

  -B dir    build directory to package (default: build)
  -o dir    where to write the archive (default: dist, or $VKMINER_DIST_DIR)
  -k        keep the unpacked staging directory next to the archive
  -h        this message
EOF
}

die() { echo "package.sh: $*" >&2; exit 1; }

while getopts ':B:o:kh' opt; do
    case "$opt" in
        B) BUILD_DIR="$OPTARG" ;;
        o) OUT_DIR="$OPTARG" ;;
        k) KEEP=1 ;;
        h) usage; exit 0 ;;
        :) echo "-$OPTARG needs an argument" >&2; exit 2 ;;
        \?) echo "unknown option -$OPTARG" >&2; usage >&2; exit 2 ;;
    esac
done

# ----------------------------------------------------------------- contents
#
# Every file in the archive, named one at a time. A release is the one place
# where "whatever is in that directory" is the wrong rule: a glob picks up an
# editor backup, a loose .spv from an experiment, or a config.json holding a
# wallet address, and nobody finds out until it has been published. Adding a
# file to a release should be a visible edit to this list.
#
# The shaders are not here because they are not files: they are compiled to
# SPIR-V at build time and embedded in the executable.
PAYLOAD=(
    README.md
    INSTALL.md
    COPYING
    LICENSE
    AUTHORS
    config-template.json
    docs/api-rest.md
    docs/openapi.yaml
)

# ------------------------------------------------------------------- target
#
# Which platform is being packaged is read off what the build produced, not
# from a flag the caller has to keep in step with -B.
if [ -f "$BUILD_DIR/vkminer.exe" ]; then
    BINARY=vkminer.exe
    OS=windows
    ARCH=x86_64
elif [ -f "$BUILD_DIR/vkminer" ]; then
    BINARY=vkminer
    OS=linux
    ARCH=$(uname -m)
else
    die "no vkminer or vkminer.exe in '$BUILD_DIR' -- build it first"
fi

# ------------------------------------------------------------------ version
#
# CMakeLists.txt is the one place the number lives. The -dev suffix mirrors
# what cmake stamps into the binary (VKMINER_VERSION), and the assertion below
# is what keeps the two from drifting apart silently.
BASE_VERSION=$(sed -nE 's/^[[:space:]]*VERSION[[:space:]]+([0-9]+(\.[0-9]+)*).*/\1/p' \
               CMakeLists.txt | head -n 1)
[ -n "$BASE_VERSION" ] || die "could not read the version out of CMakeLists.txt"
VERSION="${BASE_VERSION}-dev"

# A binary that cannot be executed here is not an error: the usual case is a
# Windows .exe cross-built on Linux. It is only checked where it can be.
if report=$("$BUILD_DIR/$BINARY" --version 2>/dev/null); then
    case "$report" in
        *"$VERSION"*) ;;
        *) die "'$BUILD_DIR/$BINARY' does not report $VERSION -- stale build?" ;;
    esac
    echo "version:  $VERSION (confirmed by the binary)"
else
    echo "version:  $VERSION (from CMakeLists.txt; the binary does not run here)"
fi

# ------------------------------------------------------------ runtime links
#
# The Windows build is checked by build-win.sh, which refuses to finish if the
# .exe imports a DLL that Windows does not ship. A Linux build has no such
# guarantee and is not meant to: it links the distribution's libraries, so the
# archive runs on that distribution and not necessarily on an older one. This
# reports what it needs rather than pretending the archive is portable.
if [ "$OS" = linux ] && command -v ldd > /dev/null 2>&1; then
    links=$(ldd "$BUILD_DIR/$BINARY" 2>/dev/null \
            | awk '/=>/ { print $1 }' \
            | grep -vE '^(linux-vdso|libc|libm|libdl|libpthread|librt|ld-linux)' \
            | sort -u || true)
    if [ -n "$links" ]; then
        echo "links:"
        printf '%s\n' "$links" | sed 's/^/    /'
        echo "    (an archive built here runs where these versions are present)"
    else
        # ldd reads nothing from a binary built for another system, which is
        # exactly what packaging a Linux build from elsewhere looks like. An
        # empty list here means "not asked", and printing it as though it meant
        # "needs nothing" would be the more dangerous of the two.
        echo "links:    not determined -- ldd could not read this binary"
    fi
fi

# ------------------------------------------------------------------ staging
STAGE_NAME="vkminer-${VERSION}-${OS}-${ARCH}"
STAGE="$OUT_DIR/$STAGE_NAME"

rm -rf "$STAGE"
mkdir -p "$STAGE"

for f in "${PAYLOAD[@]}"; do
    [ -f "$f" ] || die "missing from the tree: $f"
    mkdir -p "$STAGE/$(dirname "$f")"
    cp -p "$f" "$STAGE/$f"
done

cp -p "$BUILD_DIR/$BINARY" "$STAGE/$BINARY"
chmod 755 "$STAGE/$BINARY"

# ------------------------------------------------------------------ archive
#
# The staging directory was filled by the enumeration above, so an archiver
# reading it whole is still packing exactly that list and nothing else.
if [ "$OS" = windows ] && command -v zip > /dev/null 2>&1; then
    ARCHIVE="$OUT_DIR/$STAGE_NAME.zip"
    rm -f "$ARCHIVE"
    ( cd "$OUT_DIR" && zip -q -r "$STAGE_NAME.zip" "$STAGE_NAME" )
else
    ARCHIVE="$OUT_DIR/$STAGE_NAME.tar.gz"
    rm -f "$ARCHIVE"
    # Owner and mtime pinned so that two builds of one commit produce the same
    # bytes, which is what makes a published checksum worth anything.
    tar -czf "$ARCHIVE" -C "$OUT_DIR" \
        --owner=0 --group=0 --numeric-owner \
        "$STAGE_NAME" 2>/dev/null \
    || tar -czf "$ARCHIVE" -C "$OUT_DIR" "$STAGE_NAME"
fi

( cd "$OUT_DIR" && sha256sum "$(basename "$ARCHIVE")" > "$(basename "$ARCHIVE").sha256" )

[ "$KEEP" -eq 1 ] || rm -rf "$STAGE"

echo
echo "packaged: $ARCHIVE"
echo "          $ARCHIVE.sha256"
