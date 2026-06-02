#!/usr/bin/env sh
set -eu

TARGET="${1:-127.0.0.1}"

echo "Generating benign local lab traffic to ${TARGET}"
ping -c 3 "${TARGET}" >/dev/null 2>&1 || true

if command -v nc >/dev/null 2>&1; then
  printf 'specterids-test\n' | nc -u -w1 "${TARGET}" 5353 >/dev/null 2>&1 || true
fi

echo "Done. Use only against systems you own or are authorized to test."
