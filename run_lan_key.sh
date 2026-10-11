#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
umask 077
# Python 3.12 has established binary wheels for the crypto dependencies.
if [[ ! -x .lan-venv/bin/python ]]; then
    python3.12 -m venv .lan-venv
fi
if ! .lan-venv/bin/python -c 'import midealocal.cloud, Crypto.Cipher.AES' 2>/dev/null; then
    .lan-venv/bin/python -m pip install midea-local
fi
exec .lan-venv/bin/python obtain_lan_key.py "$@"
