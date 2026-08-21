#!/bin/sh
set -eu
mkdir -p /app/data
if [ ! -f /app/data/rsp_smart_clinic.db ] && [ -f /app/rsp_smart_clinic.db ]; then
  echo "Memigrasikan database lama ke volume persisten..."
  cp /app/rsp_smart_clinic.db /app/data/rsp_smart_clinic.db
fi
exec python server.py
