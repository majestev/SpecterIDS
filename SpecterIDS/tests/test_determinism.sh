#!/bin/sh
# Replay determinism test: run the same PCAP twice in benchmark mode and
# assert that packets_parsed, alerts, and queue_drops are identical.
# Benchmark mode forces parser_workers=1 detection_workers=1, making the
# pipeline single-threaded and the output deterministic.
set -eu

BINARY="${1:-./specterids}"
PCAP="${2:-tests/pcaps/portscan.pcap}"
PASS=0
FAIL=0

run_benchmark() {
    "$BINARY" --pcap "$PCAP" --benchmark --quiet 2>/dev/null
}

check_field() {
    field="$1"
    val1="$2"
    val2="$3"
    if [ "$val1" = "$val2" ]; then
        echo "  PASS $field: $val1"
        PASS=$((PASS + 1))
    else
        echo "  FAIL $field: run1=$val1  run2=$val2"
        FAIL=$((FAIL + 1))
    fi
}

extract() {
    output="$1"
    key="$2"
    echo "$output" | grep "^  ${key}=" | sed "s/^  ${key}=//"
}

if [ ! -f "$BINARY" ]; then
    echo "SKIP: binary '$BINARY' not found (run make first)"
    exit 0
fi

if [ ! -f "$PCAP" ]; then
    echo "SKIP: PCAP '$PCAP' not found (run make fixtures first)"
    exit 0
fi

echo "Determinism test: $PCAP"
echo "Run 1..."
out1=$(run_benchmark)
echo "Run 2..."
out2=$(run_benchmark)
echo "Run 3..."
out3=$(run_benchmark)

for field in packets_parsed alerts queue_drops malformed_packets; do
    v1=$(extract "$out1" "$field")
    v2=$(extract "$out2" "$field")
    v3=$(extract "$out3" "$field")
    check_field "$field (run1==run2)" "$v1" "$v2"
    check_field "$field (run2==run3)" "$v2" "$v3"
done

echo ""
if [ "$FAIL" -eq 0 ]; then
    echo "test_determinism: ok ($PASS checks)"
    exit 0
else
    echo "test_determinism: FAILED ($FAIL/$((PASS+FAIL)) checks)"
    exit 1
fi
