#!/bin/sh
# Check libsv2_sri:
#
#   ./test.sh [prefix]        (default: build)
#
# builds and installs the library with build.sh (which also fails on a
# stale header when cbindgen is installed), runs the crate's tests, then
# builds tests/capi_test.c against the installed header and archive and
# runs it.  CC picks the compiler; SANITIZE=1 adds AddressSanitizer and
# UndefinedBehaviorSanitizer to the C side.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
PREFIX=${1:-"$HERE/build"}
CARGO=${CARGO:-cargo}
CC=${CC:-cc}

"$HERE/build.sh" "$PREFIX"
PREFIX=$(cd "$PREFIX" && pwd)
"$CARGO" test --manifest-path "$HERE/Cargo.toml" --locked --release --target-dir "${CARGO_TARGET_DIR:-$PREFIX/target}"

CFLAGS="-std=c11 -Wall -Wextra -Werror -g -O1"
if [ "${SANITIZE:-0}" = 1 ]; then
	CFLAGS="$CFLAGS -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined"
fi
LIBS=$(PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig" pkg-config --libs --static sv2_sri 2> /dev/null ||
	PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig" pkg-config --libs sv2_sri)
# shellcheck disable=SC2086 # CFLAGS and LIBS are word lists
"$CC" $CFLAGS -I"$PREFIX/include" -o "$PREFIX/capi_test" "$HERE/tests/capi_test.c" $LIBS
"$PREFIX/capi_test"
