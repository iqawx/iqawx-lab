#!/bin/sh
# Install a supplied binary, or build it once when running from source.
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(dirname -- "$SCRIPT_DIR")
INSTALL_DIR="$HOME/.local/bin"
UPDATE_PATH=1
while [ "$#" -gt 0 ]; do
    case "$1" in
        --bin-dir) [ "$#" -ge 2 ] || exit 2; INSTALL_DIR=$2; shift 2 ;;
        --no-path) UPDATE_PATH=0; shift ;;
        *) echo "Usage: sh scripts/install.sh [--bin-dir DIRECTORY] [--no-path]" >&2; exit 2 ;;
    esac
done
BINARY="$ROOT_DIR/iqaw"
if [ ! -f "$BINARY" ]; then
    if [ -f "$ROOT_DIR/Cargo.toml" ]; then
        command -v cargo >/dev/null 2>&1 || {
            echo 'Install Rust 1.93+ to build from source, or download a prebuilt package.' >&2
            exit 1
        }
        (cd "$ROOT_DIR" && cargo build --release --locked --bin iqaw)
        BINARY="$ROOT_DIR/target/release/iqaw"
    else
        echo 'iqaw binary missing. Extract the complete package first.' >&2
        exit 1
    fi
fi
mkdir -p "$INSTALL_DIR"
# A temporary file avoids truncating a running executable on Linux.
STAGED=$(mktemp "$INSTALL_DIR/.iqaw-install.XXXXXX")
trap 'rm -f "$STAGED"' EXIT HUP INT TERM
cp "$BINARY" "$STAGED"
chmod 755 "$STAGED"
mv -f "$STAGED" "$INSTALL_DIR/iqaw"
if [ "$UPDATE_PATH" -eq 1 ]; then
    # Quote literal path characters without evaluating them in the startup file.
    ESCAPED_DIR=$(printf '%s' "$INSTALL_DIR" | sed 's/[\\"`$]/\\&/g')
    PATH_LINE="export PATH=\"$ESCAPED_DIR:\$PATH\""
    add_path() {
        if ! { [ -f "$1" ] && grep -Fqx "$PATH_LINE" "$1"; }; then
            printf '\n# IQAWX Lab command\n%s\n' "$PATH_LINE" >> "$1"
        fi
    }
    add_path "$HOME/.profile"
    case "${SHELL:-}" in
        */zsh) add_path "$HOME/.zshrc" ;;
        */bash)
            add_path "$HOME/.bashrc"
            if [ -f "$HOME/.bash_profile" ]; then add_path "$HOME/.bash_profile"; fi
            ;;
    esac
fi
printf '\nInstalled: %s/iqaw\n' "$INSTALL_DIR"
printf 'Open a new terminal, then run: iqaw\nCLI examples: iqaw --help | iqaw scan 127.0.0.1 | iqaw menu\n'
