#!/bin/bash
# WiFiWi Startup Script
fuser -k 8000/tcp || true
export PYTHONPATH=$PYTHONPATH:$(pwd)
python3 -m backend.main "$@"
