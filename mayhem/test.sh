#!/usr/bin/env bash
#
# mayhem/test.sh — RUN sniproxy's own functional suite (built by mayhem/build.sh in mayhem/build-test
# with the project's normal flags). exit 0 = pass. Emits a CTRF report.
#
#  * Upstream's C unit tests from tests/Makefile.am (assert-based; exit 0 = pass). resolv_test is
#    skipped: it resolves "localhost" through the system's DNS servers, which an offline sandbox
#    does not have.
#  * Upstream's perl functional tests (the second TESTS block, bad_dns_request_test, and
#    hostname_test/wildcard_test, which upstream CI runs too). They start mayhem/build-test/src/sniproxy
#    (they exec ../src/sniproxy, so they run from mayhem/build-test/tests), proxy real HTTP/TLS
#    connections on 127.0.0.1/localhost only, and use only core perl modules plus upstream's own
#    TestUtils/TestHTTPD. bad_dns_request_test points at 192.0.2.99, which never answers, by design.
#    Each is bounded by `timeout` (a broken sniproxy makes some hang); exit 77 = skipped, any other
#    non-zero exit (timeout included) = failed. transparent_proxy_test is skipped: it needs root and
#    a network namespace.
#  * Known-answer checks: upstream's tests/config_test parses a config and prints it back
#    (print_config); its output for sniproxy.conf and mayhem/test-data/routes.conf must equal the
#    committed golden files, so the config tokenizer/parser, the address parser and the table/listener
#    printers are checked by value, not by exit status.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"
: "${SRC:=/mayhem}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

T="$SRC/mayhem/build-test/tests"
passed=0 failed=0 skipped=0
pass() { echo "PASS: $1"; passed=$((passed + 1)); }
fail() { echo "FAIL: $1"; failed=$((failed + 1)); }

for t in address_test buffer_test cfg_tokenizer_test table_test http_test tls_test binder_test; do
  if [ ! -x "$T/$t" ]; then
    echo "missing $T/$t — mayhem/build.sh did not build the suite" >&2
    fail "$t"
    continue
  fi
  if (cd "$T" && "./$t" >"/tmp/sniproxy-$t.log" 2>&1); then pass "$t"; else fail "$t"; cat "/tmp/sniproxy-$t.log"; fi
done
echo "SKIP: resolv_test (needs a reachable DNS server)"; skipped=$((skipped + 1))

# Upstream's perl functional tests (they exec ../src/sniproxy relative to their cwd).
if [ ! -x "$SRC/mayhem/build-test/src/sniproxy" ]; then
  echo "missing mayhem/build-test/src/sniproxy — mayhem/build.sh did not build it" >&2
  fail "sniproxy binary built (mayhem/build-test/src/sniproxy)"
fi
for t in functional_test bad_request_test bind_source_test connection_reset_test fallback_test \
         fd_limit_test ipv6_v6only_test proxy_header_test reload_test reuseport_test \
         slow_client_test bad_dns_request_test hostname_test wildcard_test; do
  log="/tmp/sniproxy-$t.log"
  (cd "$T" && timeout 120 perl "$SRC/tests/$t") >"$log" 2>&1
  rc=$?
  case "$rc" in
    0)  pass "$t" ;;
    77) echo "SKIP: $t (exit 77)"; skipped=$((skipped + 1)) ;;
    *)  fail "$t (exit $rc)"; tail -n 50 "$log" ;;
  esac
done
echo "SKIP: transparent_proxy_test (needs root and a network namespace)"; skipped=$((skipped + 1))

# Known-answer: config_test's print_config output vs. the golden files.
for conf in sniproxy.conf mayhem/test-data/routes.conf; do
  name="config_test:$(basename "$conf")"
  expected="mayhem/test-data/$(basename "$conf").expected"
  out="/tmp/sniproxy-$(basename "$conf").out"
  (cd "$SRC" && "$T/config_test" "$conf" >"$out" 2>/dev/null)
  if [ -s "$out" ] && diff -u "$expected" "$out"; then pass "$name"; else fail "$name"; fi
done

emit_ctrf "sniproxy-unit+perl+config-golden" "$passed" "$failed" "$skipped"
