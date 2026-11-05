#!/bin/sh
set -eu
cd -- "$(dirname -- "$0")"
if [ -x ./iqaw ]; then exec ./iqaw; fi
if [ -x ./target/release/iqaw ]; then exec ./target/release/iqaw; fi
printf 'Run sh scripts/install.sh once, then open this shortcut again.\n'
printf 'Press Enter to close.\n'
read -r unused
