#!/usr/bin/env bash
set -euo pipefail
cd /home/ubuntu/web-service/cpsm-server
if [[ ! -r .env ]]; then
  printf '%s\n' 'cpsm-server .env is missing' >&2
  exit 1
fi
set -a
source ./.env
set +a
exec /usr/bin/node src/index.js
