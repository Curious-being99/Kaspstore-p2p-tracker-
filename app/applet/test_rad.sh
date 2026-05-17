#!/bin/bash
export HOME="/app/applet/rad_home"
mkdir -p "$HOME/.radicle/keys"
echo "testkey12345testkey12345testkey12" > "$HOME/.radicle/keys/radicle"
chmod 600 "$HOME/.radicle/keys/radicle"

curl -sSfL https://radicle.xyz/install | sh
export PATH="$HOME/.radicle/bin:$PATH"

rad node start || echo "node start failed"
rad sync || echo "sync failed"
