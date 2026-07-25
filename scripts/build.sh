#!/usr/bin/env sh
# SPDX-License-Identifier: GPL-3.0-only

set -eu

REPOSITORY_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VERSION=$(sed -n 's/^version=//p' "$REPOSITORY_ROOT/module/module.prop")
REQUESTED_OUTPUT=${1:-"$REPOSITORY_ROOT/dist/keybox-rotator-$VERSION.zip"}
OUTPUT_DIRECTORY=$(dirname -- "$REQUESTED_OUTPUT")
OUTPUT_NAME=$(basename -- "$REQUESTED_OUTPUT")

mkdir -p "$OUTPUT_DIRECTORY"
OUTPUT_DIRECTORY=$(CDPATH= cd -- "$OUTPUT_DIRECTORY" && pwd)
OUTPUT_PATH="$OUTPUT_DIRECTORY/$OUTPUT_NAME"
BUILD_DIRECTORY=$(mktemp -d)
STAGING_DIRECTORY="$BUILD_DIRECTORY/payload"
TEMPORARY_ARCHIVE="$BUILD_DIRECTORY/module.zip"
mkdir -p "$STAGING_DIRECTORY"

cleanup() {
    rm -rf "$BUILD_DIRECTORY"
}
trap cleanup EXIT HUP INT TERM

cp -R "$REPOSITORY_ROOT/module/." "$STAGING_DIRECTORY/"
cp "$REPOSITORY_ROOT/LICENSE" "$STAGING_DIRECTORY/LICENSE"
cp "$REPOSITORY_ROOT/NOTICE.md" "$STAGING_DIRECTORY/NOTICE.md"
rm -rf "$STAGING_DIRECTORY/__pycache__"

(cd "$STAGING_DIRECTORY" && zip -q -r "$TEMPORARY_ARCHIVE" . -x '*.pyc' '*.pyo')
mv -f "$TEMPORARY_ARCHIVE" "$OUTPUT_PATH"
sha256sum "$OUTPUT_PATH"
