#!/bin/sh
# Build only the native encoder/decoder tool, never instruction models.
set -eu
: "${XED_ROOT:?set the cached XED package path}"
: "${CC:?set the compiler path}"
source_file=$1
output=$2
"$CC" -O0 -fPIC -shared -I"$XED_ROOT/include" "$source_file" "$XED_ROOT/lib/libxed-enc2-m64-a64.a" "$XED_ROOT/lib/libxed.a" -o "$output"
