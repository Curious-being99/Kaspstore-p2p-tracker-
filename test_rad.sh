#!/bin/bash
export HOME="/tmp/rad_home"
rm -rf "$HOME"
mkdir -p "$HOME/.radicle/keys"
# Generate a test ed25519 key WITH a passphrase "testpass"
ssh-keygen -t ed25519 -N "testpass" -f "$HOME/.radicle/keys/radicle" -C ""
curl -sSfL https://radicle.xyz/install | sh
export PATH="$HOME/.radicle/bin:$PATH"

export RAD_PASSPHRASE="testpass"

# Try starting rad node
rad node start
rad sync || true
