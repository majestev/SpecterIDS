#!/bin/sh
# Offline-input hardening test: feed SpecterIDS untrusted PCAP containers and
# assert it never crashes. A crash shows up as termination by signal (exit
# code >= 128, e.g. 134=SIGABRT from a sanitizer, 139=SIGSEGV). Run this against
# the ASan/UBSan build (make debug) for the strongest coverage.
#
# Cases:
#   corrupt.pcap -> invalid magic number: must fail to open (clean non-zero exit)
#   empty.pcap   -> valid header, zero records: must succeed (clean EOF, exit 0)
set -u

BINARY="${1:-./specterids}"
PASS=0
FAIL=0

if [ ! -f "$BINARY" ]; then
    echo "SKIP: binary '$BINARY' not found (run make first)"
    exit 0
fi

# check_no_crash <label> <pcap> <expectation: fail|succeed>
check_no_crash() {
    label="$1"
    pcap="$2"
    expect="$3"

    if [ ! -f "$pcap" ]; then
        echo "  SKIP $label: '$pcap' not found (run make fixtures first)"
        return
    fi

    "$BINARY" --pcap "$pcap" --quiet >/dev/null 2>&1
    rc=$?

    if [ "$rc" -ge 128 ]; then
        echo "  FAIL $label: terminated by signal (exit=$rc)"
        FAIL=$((FAIL + 1))
        return
    fi

    case "$expect" in
        fail)
            if [ "$rc" -ne 0 ]; then
                echo "  PASS $label: clean failure, no crash (exit=$rc)"
                PASS=$((PASS + 1))
            else
                echo "  FAIL $label: expected non-zero exit, got 0"
                FAIL=$((FAIL + 1))
            fi
            ;;
        succeed)
            if [ "$rc" -eq 0 ]; then
                echo "  PASS $label: clean success, no crash (exit=$rc)"
                PASS=$((PASS + 1))
            else
                echo "  FAIL $label: expected exit 0, got $rc"
                FAIL=$((FAIL + 1))
            fi
            ;;
    esac
}

echo "PCAP error-handling test"
check_no_crash "corrupt container (bad magic)" tests/pcaps/corrupt.pcap fail
check_no_crash "empty container (header only)" tests/pcaps/empty.pcap   succeed

echo ""
if [ "$FAIL" -eq 0 ]; then
    echo "test_pcap_errors: ok ($PASS checks)"
    exit 0
else
    echo "test_pcap_errors: FAILED ($FAIL/$((PASS + FAIL)) checks)"
    exit 1
fi
