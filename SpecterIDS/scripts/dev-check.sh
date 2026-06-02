#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."
make clean
make
make debug
make release
make test
make fuzz
make analyze
