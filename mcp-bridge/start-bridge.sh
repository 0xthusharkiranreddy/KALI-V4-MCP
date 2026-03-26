#!/bin/sh
# SSH pool init + reconnection watchdog, then start the Node bridge.
# Usage (set as CMD in Dockerfile): /start-bridge.sh bridge-server.js
#         or                        /start-bridge.sh desktop-bridge-server.js
set -euo pipefail
: "${KALI_HOST:?KALI_HOST is required}"
: "${KALI_USERNAME:?KALI_USERNAME is required}"
: "${KALI_PORT:?KALI_PORT is required}"

# ─── SSH key ──────────────────────────────────────────────────────────────────
mkdir -p /root/.ssh
cp /mnt/host-keys/id_ed25519 /root/.ssh/id_ed25519
chmod 600 /root/.ssh/id_ed25519
echo "SSH key ready"

POOL_SIZE=${SSH_POOL_SIZE:-5}
KALI_PORT=${KALI_PORT:-22}
echo "Establishing SSH pool of ${POOL_SIZE} connections to ${KALI_USERNAME}@${KALI_HOST}:${KALI_PORT}..."

# ─── Start ControlMaster connections ─────────────────────────────────────────
i=1
while [ "$i" -le "$POOL_SIZE" ]; do
  ssh -i /root/.ssh/id_ed25519 -p ${KALI_PORT} \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ControlMaster=yes \
    -o ControlPath=/tmp/ssh_mux_${KALI_HOST}_${i} \
    -o ControlPersist=yes \
    -N ${KALI_USERNAME}@${KALI_HOST} &
  i=$((i + 1))
done

# ─── Wait up to 60s for at least one connection ───────────────────────────────
MAX_WAIT=60
elapsed=0
READY=0
while [ "$elapsed" -lt "$MAX_WAIT" ]; do
  READY=0
  i=1
  while [ "$i" -le "$POOL_SIZE" ]; do
    if ssh -p ${KALI_PORT} -o ControlPath=/tmp/ssh_mux_${KALI_HOST}_${i} \
         -O check ${KALI_USERNAME}@${KALI_HOST} 2>/dev/null; then
      READY=$((READY + 1))
    fi
    i=$((i + 1))
  done
  [ "$READY" -gt 0 ] && break
  sleep 2
  elapsed=$((elapsed + 2))
done

echo "SSH pool ready: ${READY}/${POOL_SIZE} connections established"

if [ "$READY" -eq 0 ]; then
  echo "ERROR: No SSH connections after ${MAX_WAIT}s — is ${KALI_HOST} reachable?"
  exit 1
fi

# ─── Background pool watchdog — reconnects dead sockets every 30s ─────────────
(
  while true; do
    sleep 30
    i=1
    while [ "$i" -le "$POOL_SIZE" ]; do
      if ! ssh -p ${KALI_PORT} -o ControlPath=/tmp/ssh_mux_${KALI_HOST}_${i} \
               -O check ${KALI_USERNAME}@${KALI_HOST} 2>/dev/null; then
        echo "Pool socket ${i} dead — reconnecting..."
        ssh -i /root/.ssh/id_ed25519 -p ${KALI_PORT} \
          -o StrictHostKeyChecking=no \
          -o UserKnownHostsFile=/dev/null \
          -o ControlMaster=yes \
          -o ControlPath=/tmp/ssh_mux_${KALI_HOST}_${i} \
          -o ControlPersist=yes \
          -N ${KALI_USERNAME}@${KALI_HOST} &
      fi
      i=$((i + 1))
    done
  done
) &

# ─── Start Node bridge ────────────────────────────────────────────────────────
echo "Starting Node.js: $1"
exec node "$1"
