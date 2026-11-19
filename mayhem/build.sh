#!/usr/bin/env bash
#
# mayhem/build.sh — build sniproxy's fuzz harnesses and its own unit tests.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. Re-runnable and
# offline: every dependency (libev, pcre2, udns, autotools) comes from the image.
#
#   1. autoreconf (generates configure & Makefile.in in-tree; all gitignored upstream).
#   2. mayhem/build-fuzz: upstream's configure + make with ASan/UBSan + SanCov + DWARF 3, then each
#      harness in mayhem/harnesses/ linked against the project objects (all but sniproxy.o) twice:
#      the libFuzzer binary /mayhem/<h> and the run-once reproducer /mayhem/<h>-standalone.
#   3. mayhem/build-test: a separate configure + make with the project's NORMAL flags, plus the
#      tests/ unit-test programs that mayhem/test.sh runs.
# Both build dirs are out of tree and gitignored (mayhem/.gitignore).
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
: "${STANDALONE_FUZZ_MAIN:?STANDALONE_FUZZ_MAIN must point at the base image run-once driver}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

HARNESSES=(fuzz_tls fuzz_http fuzz_config fuzz_address fuzz_lookup)
cd "$SRC"

# 1) Generate the build system (upstream's autogen.sh also runs setver.sh, which rewrites tracked
#    files, so call autoreconf directly).
autoreconf --install

# 2) Sanitized + coverage-instrumented project build. -fsanitize=fuzzer-no-link puts SanCov on the
#    project objects (not only the harness TU), unconditionally, even with SANITIZER_FLAGS empty.
#    UBSan relaxations (only these two checks; ASan and the rest of UBSan stay on and halting):
#    - function: sniproxy calls through deliberately mismatched function-pointer types by design
#      (tls_protocol->parse_packet is `int (*)(const char *, ...)` over parse_tls_header(const
#      uint8_t *, ...); cfg_parser.c invokes every keyword builder as `void *(*)(void)`), so the
#      check fires on every input of every target before any input-dependent code runs.
#    - alignment: struct Address stores its sockaddr in a `char data[]` at offset 18 (address.c),
#      so every IPv4/IPv6 address is accessed misaligned; benign on x86, but it fires on any
#      numeric address. Out-of-bounds accesses are still caught by ASan.
UBSAN_RELAX=""
case "$SANITIZER_FLAGS" in *undefined*) UBSAN_RELAX="-fno-sanitize=function,alignment" ;; esac
SANITIZER_FLAGS="$SANITIZER_FLAGS $UBSAN_RELAX"
FUZZ_CFLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS -O1"
mkdir -p mayhem/build-fuzz
(
  cd mayhem/build-fuzz
  "$SRC/configure" --enable-dns CC="$CC" CFLAGS="$FUZZ_CFLAGS" LDFLAGS="$SANITIZER_FLAGS" >/dev/null
  make -j"$MAYHEM_JOBS" -C src
)

# The project's own configure-detected defines (HAVE_LIBPCRE2_8 changes struct Backend's layout,
# so the harnesses must see the same ones as the objects they link).
eval "DEFS=($(sed -n 's/^DEFS = //p' mayhem/build-fuzz/src/Makefile))"
LIBS=$(sed -n 's/^LIBS = //p' mayhem/build-fuzz/src/Makefile)
PROJECT_OBJS=()
for o in mayhem/build-fuzz/src/*.o; do
  [ "$(basename "$o")" = sniproxy.o ] || PROJECT_OBJS+=("$o")
done

$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o mayhem/build-fuzz/lsan_off.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c -x c "$STANDALONE_FUZZ_MAIN" -o mayhem/build-fuzz/standalone_main.o

# fuzz_config: an input's error_log/access_log `filename` is fopen()ed for append by logger.c, so
# that harness wraps libc fopen to keep those writes in its scratch dir (see the harness header).
declare -A HARNESS_LDFLAGS=([fuzz_config]="-Wl,--wrap=fopen")

for h in "${HARNESSES[@]}"; do
  extra="${HARNESS_LDFLAGS[$h]:-}"
  $CC $SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS -O1 "${DEFS[@]}" -I"$SRC/src" \
      -c "mayhem/harnesses/$h.c" -o "mayhem/build-fuzz/$h.o"
  # shellcheck disable=SC2086
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "mayhem/build-fuzz/$h.o" \
      "${PROJECT_OBJS[@]}" mayhem/build-fuzz/lsan_off.o $LIBS $extra -o "/mayhem/$h"
  # shellcheck disable=SC2086
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS mayhem/build-fuzz/standalone_main.o "mayhem/build-fuzz/$h.o" \
      "${PROJECT_OBJS[@]}" mayhem/build-fuzz/lsan_off.o $LIBS $extra -o "/mayhem/$h-standalone"
done

# 3) The functional suite with the project's normal flags (configure's default -g -O2), in its own
#    out-of-tree dir: sniproxy itself plus the unit-test programs from tests/Makefile.am.
mkdir -p mayhem/build-test
(
  cd mayhem/build-test
  env -u CFLAGS -u LDFLAGS "$SRC/configure" --enable-dns CC="$CC" \
      CFLAGS="-g -O2 $COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS" >/dev/null
  make -j"$MAYHEM_JOBS"
  make -C tests http_test tls_test table_test binder_test buffer_test cfg_tokenizer_test \
       address_test resolv_test config_test
)
