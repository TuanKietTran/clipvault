#!/bin/sh
set -eu
cd "$(dirname "$0")"
swift test --package-path ../vault
swift build
python3 -m unittest discover -s Tests -p 'test_*.py'
