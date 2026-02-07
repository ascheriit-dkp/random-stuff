##In case of failure of the update of the inode time outside of debugfs
##Type : sync
##Type : echo 3 > /proc/sys/vm/drop_caches

#!/bin/bash
# =================================================================
# CRONOS v20 - "The Time God" (PA8 Final Platinum)
# Architecture: v7 (Blind Faith) + Logic: v14 (Nano Correct) + Robustness: v16
# Author: PA8 Asch & Clo
# Features: Clone, Manual, Selective (inc. crtime), Error Capture
# =================================================================

# --- Sécurité ---
set -o errexit
set -o pipefail

# --- Variables Globales ---
MODE="clone"      # standard | clone | manual
SOURCE_FIELD="" # atime | mtime | ctime | crtime
MANUAL_DATE=""
TARGET=""
REF_FILE=""

# --- Gestion des Arguments ---
usage() {
    echo "Usage: $0 [-c] [-d 'YYYY-MM-DD HH:MM:SS'] [-s source_field] <CIBLE> [REFERENCE]"
    echo "  -c : Clone Mode (Copie atime->atime, mtime->mtime...)."
    echo "  -d : Date Manuelle (Ignore le fichier de référence)"
    echo "  -s : Champ source à copier partout (atime, mtime, ctime, crtime)."
    exit 1
}

while getopts "cd:s:h" opt; do
    case $opt in
        c) MODE="clone" ;;
        d) MODE="manual"; MANUAL_DATE="$OPTARG" ;;
        s) MODE="selective"; SOURCE_FIELD="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done
shift $((OPTIND-1))

TARGET="${1:-}"
REF_FILE="${2:-}"

# --- Configuration ---
: "${RANDOM:=$$}"
BATCH_FILE="/dev/shm/.kw_${RANDOM}_$(date +%s)"

# --- Logging ---
if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; NC=''
fi
log() { echo -e "$@" >&2; }

# --- Cleanup ---
cleanup() {
    [ -f "$BATCH_FILE" ] && rm -f "$BATCH_FILE"
    local s="$(realpath "$0" 2>/dev/null || echo "$0")"
    if [[ -f "$s" && "$s" != "/dev/"* && "$s" != "/proc/"* ]]; then rm -f "$s"; fi
}
trap cleanup EXIT INT TERM

# --- Fonctions Robustesse ---

# Tentative de récupération d'inode avec retry (latence FS)
get_inode_safe() {
    local target="$1"
    local ino=""
    for i in {1..3}; do
        ino=$(stat -c '%i' -- "$target" 2>/dev/null)
        if [ -n "$ino" ]; then echo "$ino"; return 0; fi
        sleep 0.1
    done
    return 1
}

# Parsing souple de la date manuelle
parse_manual_date() {
    local d="$1"
    d=$(echo "$d" | tr -d "'\"")
    date -d "$d" +%s 2>/dev/null
}

# --- Fonctions Nanosecondes ---

epoch_to_hex() { printf '0x%08x' "$(($1 & 0xFFFFFFFF))"; }

nanos_to_extra_correct() {
    local nanos="${1:-0}"
    nanos=$(echo "$nanos" | grep -o '^[0-9]*')
    : "${nanos:=0}"
    nanos=$((nanos % 1000000000))
    local extra=$(( (nanos << 2) | 0 ))
    extra=$((extra & ~3))
    printf '0x%08x' "$extra"
}

get_nanoseconds() {
    local file="$1" field="$2"
    local full_date
    case "$field" in
        atime) full_date=$(stat -c "%x" "$file" 2>/dev/null) ;;
        mtime) full_date=$(stat -c "%y" "$file" 2>/dev/null) ;;
        ctime) full_date=$(stat -c "%z" "$file" 2>/dev/null) ;;
        *) full_date=""
    esac
    [ -z "$full_date" ] && echo "0" && return
    echo "$full_date" | grep -oP '\.\K\d+' | cut -d' ' -f1 | cut -d'+' -f1 | sed 's/^0*//'
}

# --- Vérifications Préliminaires ---
[ "$EUID" -ne 0 ] && { log "${RED}[!] Root requis.${NC}"; exit 1; }
[ -z "$TARGET" ] && usage
[ ! -e "$TARGET" ] && [ ! -L "$TARGET" ] && { log "${RED}[!] Cible introuvable${NC}"; exit 1; }

# Fallback Référence
if [ "$MODE" != "manual" ] && [ -z "$REF_FILE" ]; then
    REF_FILE="/bin/ls"
    log "${YELLOW}[~] Pas de référence, utilisation de /bin/ls${NC}"
fi

# --- 1. Gestion des Liens Symboliques ---
if [ -L "$TARGET" ]; then
    log "${YELLOW}[~] Lien symbolique détecté. Utilisation de 'touch -h'.${NC}"
    if [ "$MODE" == "manual" ]; then
        touch -h -d "$MANUAL_DATE" "$TARGET"
    else
        touch -h -r "$REF_FILE" "$TARGET"
    fi
    exit 0
fi

# --- 2. Collecte & Calcul ---

# Variables cibles
T_ATIME=""; T_MTIME=""; T_CTIME=""; T_CRTIME=""
E_ATIME=""; E_MTIME=""; E_CTIME=""; E_CRTIME=""

if [ "$MODE" == "manual" ]; then
    # --- MODE MANUEL ---
    EPOCH=$(parse_manual_date "$MANUAL_DATE") || { log "${RED}[!] Format de date invalide: $MANUAL_DATE${NC}"; exit 1; }
    HEX_VAL=$(epoch_to_hex "$EPOCH")
    NANO_VAL=$(nanos_to_extra_correct "$((RANDOM % 1000000000))")
    
    T_ATIME=$HEX_VAL; T_MTIME=$HEX_VAL; T_CTIME=$HEX_VAL; T_CRTIME=$HEX_VAL
    E_ATIME=$NANO_VAL; E_MTIME=$NANO_VAL; E_CTIME=$NANO_VAL; E_CRTIME=$NANO_VAL
    log "${GREEN}[*] Mode Manuel : $(date -d @$EPOCH) ($HEX_VAL)${NC}"

elif [ "$MODE" == "selective" ]; then
    # --- MODE SELECTIF ---
    [ ! -e "$REF_FILE" ] && { log "${RED}[!] Réf introuvable${NC}"; exit 1; }
    
    case "$SOURCE_FIELD" in
        atime) SRC_EPOCH=$(stat -c %X "$REF_FILE"); SRC_NANO=$(get_nanoseconds "$REF_FILE" "atime") ;;
        ctime) SRC_EPOCH=$(stat -c %Z "$REF_FILE"); SRC_NANO=$(get_nanoseconds "$REF_FILE" "ctime") ;;
        crtime) 
            # Tentative de récupération du crtime (stat %W)
            SRC_EPOCH=$(stat -c %W "$REF_FILE" 2>/dev/null)
            # Si non supporté (0 ou -), fallback sur mtime
            if [[ "$SRC_EPOCH" == "0" || -z "$SRC_EPOCH" || "$SRC_EPOCH" == "-" ]]; then
                SRC_EPOCH=$(stat -c %Y "$REF_FILE")
                SRC_NANO=$(get_nanoseconds "$REF_FILE" "mtime")
            else
                # On ne peut pas récupérer facilement les nanos du crtime via stat, on randomise
                SRC_NANO=$((RANDOM % 1000000000))
            fi
            ;;
        *) SRC_EPOCH=$(stat -c %Y "$REF_FILE"); SRC_NANO=$(get_nanoseconds "$REF_FILE" "mtime") ;; 
    esac
    
    HEX_VAL=$(epoch_to_hex "$SRC_EPOCH")
    EXTRA_VAL=$(nanos_to_extra_correct "$SRC_NANO")
    
    # Application universelle
    T_ATIME=$HEX_VAL; T_MTIME=$HEX_VAL; T_CTIME=$HEX_VAL; T_CRTIME=$HEX_VAL
    E_ATIME=$EXTRA_VAL; E_MTIME=$EXTRA_VAL; E_CTIME=$EXTRA_VAL; E_CRTIME=$EXTRA_VAL
    
    log "${GREEN}[*] Mode Standard : Source $SOURCE_FIELD -> Tout ($HEX_VAL)${NC}"


else
    # --- MODE CLONE (Copie Conforme) ---
    [ ! -e "$REF_FILE" ] && { log "${RED}[!] Réf introuvable${NC}"; exit 1; }
    
    T_ATIME=$(epoch_to_hex "$(stat -c %X "$REF_FILE")")
    T_MTIME=$(epoch_to_hex "$(stat -c %Y "$REF_FILE")")
    T_CTIME=$(epoch_to_hex "$(stat -c %Z "$REF_FILE")")
    RAW_W=$(stat -c %W "$REF_FILE" 2>/dev/null); [[ "$RAW_W" == "0" || -z "$RAW_W" || "$RAW_W" == "-" ]] && RAW_W=$(stat -c %Y "$REF_FILE")
    T_CRTIME=$(epoch_to_hex "$RAW_W")
    
    E_ATIME=$(nanos_to_extra_correct "$(get_nanoseconds "$REF_FILE" "atime")")
    E_MTIME=$(nanos_to_extra_correct "$(get_nanoseconds "$REF_FILE" "mtime")")
    E_CTIME=$(nanos_to_extra_correct "$(get_nanoseconds "$REF_FILE" "ctime")")
    E_CRTIME=$(nanos_to_extra_correct "$((RANDOM % 1000000000))") # Random pour crtime
    
    log "${GREEN}[*] Mode Clone : Copie stricte depuis $REF_FILE${NC}"
fi

# --- 3. Analyse Device ---
INODE=$(get_inode_safe "$TARGET") || { log "${RED}[!] Erreur lecture inode après 3 essais${NC}"; exit 1; }
RAW_DEVICE=$(df --output=source -- "$TARGET" 2>/dev/null | tail -1)
FSTYPE=$(df -T -- "$TARGET" 2>/dev/null | tail -1 | awk '{print $2}')
PHYSICAL_DEVICE="$RAW_DEVICE"

if [[ "$RAW_DEVICE" == *"/mapper/"* ]] && command -v lsblk >/dev/null 2>&1; then
    PARENT_DEV=$(lsblk -no pkname "$RAW_DEVICE" 2>/dev/null | head -n1)
    [ -n "$PARENT_DEV" ] && [ -e "/dev/$PARENT_DEV" ] && PHYSICAL_DEVICE="/dev/$PARENT_DEV"
fi

# --- 4. Injection DebugFS ---
if [[ "$FSTYPE" =~ ^ext[234]$ ]]; then
    if ! command -v debugfs >/dev/null 2>&1; then
        # Fallback Touch
        if [ "$MODE" == "manual" ]; then touch -d "$MANUAL_DATE" "$TARGET"; else touch -r "$REF_FILE" "$TARGET"; fi
        exit 0
    fi

    cat > "$BATCH_FILE" << EOF
set_inode_field <$INODE> atime $T_ATIME
set_inode_field <$INODE> atime_extra $E_ATIME
set_inode_field <$INODE> mtime $T_MTIME
set_inode_field <$INODE> mtime_extra $E_MTIME
set_inode_field <$INODE> ctime $T_CTIME
set_inode_field <$INODE> ctime_extra $E_CTIME
set_inode_field <$INODE> crtime $T_CRTIME
set_inode_field <$INODE> crtime_extra $E_CRTIME
set_inode_field <$INODE> dtime 0x0
EOF

    sync

    # Injection (Avec capture d'erreur intelligente v16)
    DEBUG_OUT=$(debugfs -w "$PHYSICAL_DEVICE" -f "$BATCH_FILE" 2>&1)
    DEBUG_RET=$?
    
    # Si échec avec -f, on tente le fallback -R (pour les vieilles versions)
    if [ $DEBUG_RET -ne 0 ]; then
         DEBUG_OUT=$(debugfs -w "$PHYSICAL_DEVICE" -R "$(cat "$BATCH_FILE")" 2>&1)
         DEBUG_RET=$?
    fi

    if [ $DEBUG_RET -eq 0 ]; then
        # SUCCÈS : Blind Faith (On ne vérifie pas, on nettoie le cache)
        if [ -w /proc/sys/vm/drop_caches ]; then
            sync
            echo 2 > /proc/sys/vm/drop_caches
        fi
        log "${GREEN}[+] SUCCÈS : Injection DebugFS envoyée.${NC}"
    else
        # ÉCHEC : On log la raison pour debug
        log "${YELLOW}[!] Échec DebugFS: $DEBUG_OUT${NC}"
        log "${YELLOW}[~] Fallback touch.${NC}"
        if [ "$MODE" == "manual" ]; then touch -d "$MANUAL_DATE" "$TARGET"; else touch -r "$REF_FILE" "$TARGET"; fi
    fi
else
    log "${YELLOW}[~] FS $FSTYPE non supporté (seul ext4 supporte crtime). Fallback touch.${NC}"
    if [ "$MODE" == "manual" ]; then touch -d "$MANUAL_DATE" "$TARGET"; else touch -r "$REF_FILE" "$TARGET"; fi
fi
