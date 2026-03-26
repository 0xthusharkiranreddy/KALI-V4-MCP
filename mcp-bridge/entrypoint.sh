#!/bin/sh
set -e

if [ -f /mnt/host-keys/id_ed25519 ]; then
    echo "Copying SSH key to secure location..."
    cp /mnt/host-keys/id_ed25519 /tmp/keys/id_ed25519
    chmod 600 /tmp/keys/id_ed25519
    chown mcpuser:mcpuser /tmp/keys/id_ed25519
    echo "SSH key ready at /tmp/keys/id_ed25519"
else
    echo "ERROR: SSH key not found at /mnt/host-keys/id_ed25519" >&2
    exit 1
fi

exec "\$@"
