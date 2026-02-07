#!/usr/bin/env bash
set -euo pipefail

IN="${1:-public_key.pem}"

echo '// --- CONFIGURATION ---'
echo '// Collez ce #define dans votre code :'
echo '#define RSA_PUB_KEY "-----BEGIN PUBLIC KEY-----\n" \'

# On enlève les lignes BEGIN/END, on met chaque ligne base64 dans "...\n" \
sed -n '1,${p}' "$IN" \
  | sed '/-----BEGIN PUBLIC KEY-----/d; /-----END PUBLIC KEY-----/d' \
  | sed 's/\\/\\\\/g; s/"/\\"/g' \
  | sed 's/^/"/; s/$/\\n" \\/'

echo '"-----END PUBLIC KEY-----\n"'
