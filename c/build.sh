#!/bin/sh
# Build libsv2_sri (the SRI crates behind a C API) and install it into a
# prefix that pkg-config can find:
#
#   ./build.sh [prefix]        (default: build)
#
#   <prefix>/lib/libsv2_sri.a
#   <prefix>/include/sv2_sri.h
#   <prefix>/lib/pkgconfig/sv2_sri.pc
#
# Needs cargo (CARGO overrides which one) and network access the first
# time, to fetch the crates; Cargo.lock pins their versions.
# CARGO_TARGET_DIR is honoured; by default the build goes in <prefix>/target.
# When cbindgen is installed, the committed header is checked against the
# sources and the build fails if it is stale.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
PREFIX=${1:-"$HERE/build"}
mkdir -p "$PREFIX"
PREFIX=$(cd "$PREFIX" && pwd)
CARGO=${CARGO:-cargo}
# the C parts of the crates (libsecp256k1) target the running macOS, as the
# C code linked with them does
if [ "$(uname)" = Darwin ] && [ -z "${MACOSX_DEPLOYMENT_TARGET:-}" ]; then
	MACOSX_DEPLOYMENT_TARGET=$(sw_vers -productVersion | cut -d. -f1).0
	export MACOSX_DEPLOYMENT_TARGET
fi
TARGET_DIR=${CARGO_TARGET_DIR:-"$PREFIX/target"}

if command -v cbindgen > /dev/null 2>&1; then
	cbindgen --quiet --config "$HERE/cbindgen.toml" --crate sv2_sri --output "$TARGET_DIR/sv2_sri.h" "$HERE"
	if ! cmp -s "$TARGET_DIR/sv2_sri.h" "$HERE/include/sv2_sri.h"; then
		echo "include/sv2_sri.h is stale; regenerate it with:" >&2
		echo "  cbindgen --config cbindgen.toml --crate sv2_sri --output include/sv2_sri.h ." >&2
		exit 1
	fi
fi

# A static library does not record the system libraries it needs; rustc
# prints them when asked.  The note only appears when rustc actually runs,
# so keep the last one next to the build.
NOTE="$TARGET_DIR/native-static-libs.txt"
"$CARGO" rustc --manifest-path "$HERE/Cargo.toml" --locked --release --lib --crate-type staticlib \
	--target-dir "$TARGET_DIR" -- --print native-static-libs 2> "$TARGET_DIR.log" || { cat "$TARGET_DIR.log" >&2; exit 1; }
sed -n 's/.*native-static-libs: //p' "$TARGET_DIR.log" | tail -n 1 > "$NOTE.new"
if [ -s "$NOTE.new" ]; then mv "$NOTE.new" "$NOTE"; else rm -f "$NOTE.new"; fi
[ -s "$NOTE" ] || { echo "rustc did not report native-static-libs; remove $TARGET_DIR and retry" >&2; exit 1; }
# drop repeats (rustc lists libc and libm twice on some targets)
NATIVE=$(tr ' ' '\n' < "$NOTE" | awk 'NF && !seen[$0]++' | tr '\n' ' ' | sed 's/ $//')

mkdir -p "$PREFIX/lib/pkgconfig" "$PREFIX/include"
cp "$TARGET_DIR/release/libsv2_sri.a" "$PREFIX/lib/"
cp "$HERE/include/sv2_sri.h" "$PREFIX/include/"
cat > "$PREFIX/lib/pkgconfig/sv2_sri.pc" <<PC
prefix=$PREFIX
libdir=\${prefix}/lib
includedir=\${prefix}/include

Name: sv2_sri
Description: Stratum V2 protocol layer from the SRI crates behind a C API (prototype)
Version: $(sed -n 's/^version = "\(.*\)"/\1/p' "$HERE/Cargo.toml" | head -n 1)
Libs: -L\${libdir} -lsv2_sri $NATIVE
Cflags: -I\${includedir}
PC
echo "installed: $PREFIX (PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig)"
