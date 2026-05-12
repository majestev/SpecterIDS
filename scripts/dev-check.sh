#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."
make
make test
make fuzz
make analyze
