#!/bin/sh
set -e

# Start system D-Bus daemon
mkdir -p /var/run/dbus
dbus-daemon --system --nofork --nopidfile &
DBUS_SYSTEM_PID=$!

# Start session D-Bus daemon
eval $(dbus-launch --sh-syntax)
export DBUS_SESSION_BUS_ADDRESS

# Wait for D-Bus to start
sleep 1

# Create keyring directories
mkdir -p ~/.cache
mkdir -p ~/.local/share/keyrings

# 1. Create the keyring manually with a dummy password (newline)
# This creates the login keyring if it doesn't exist
eval "$(printf '\n' | gnome-keyring-daemon --unlock)"

# 2. Start the daemon, using the password to unlock the just-created keyring
eval "$(printf '\n' | gnome-keyring-daemon --start)"

# Wait for the keyring to be fully ready
sleep 1

# Start the application
exec ./nostr-oidc
