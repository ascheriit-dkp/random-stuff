#!/bin/bash

# ==============================================================================
#  CONFIGURATION DE RESTAURATION
# ==============================================================================

SPECTATOR_USER_PREFIX="guest_"
RESET_ROOT_PASS="root"
PRIV_KEY="./private_key.pem"

TARGET_DIRS=(
    "/var/www"
    "/etc/apache2" "/etc/httpd" "/etc/nginx"
    "/etc/haproxy" "/etc/squid"
    "/etc/bind" "/var/named"
    "/etc/postfix" "/etc/mysql" "/var/lib/mysql"
    "/home" "/root" "/opt"
)

SERVICES_TO_RESTORE=(
    "apache2" "httpd" "nginx" "mysql" "mariadb" "postgresql"
    "bind9" "named" "postfix" "docker"
)

# ==============================================================================
#  LOGIQUE DE RÉPARATION
# ==============================================================================

[[ $EUID -ne 0 ]] && echo "Must be root" >&2 && exit 1

if [ ! -f "$PRIV_KEY" ]; then 
    echo "ERREUR: Fichier '$PRIV_KEY' introuvable."
    exit 1
fi

echo "[*] Phase 1 : Nettoyage des accès..."

echo "root:$RESET_ROOT_PASS" | chpasswd

DETECTED_USER=$(grep "^$SPECTATOR_USER_PREFIX" /etc/passwd | cut -d: -f1 | head -n 1)
if [ -n "$DETECTED_USER" ]; then
    chattr -i "/home/$DETECTED_USER/INSTRUCTIONS.txt" 2>/dev/null
    pkill -KILL -u "$DETECTED_USER" 2>/dev/null
    userdel -r "$DETECTED_USER" 2>/dev/null
    echo "   -> Intrus supprimé."
fi

echo -e "Debian GNU/Linux \n \l" > /etc/issue

echo "[*] Phase 2 : Déchiffrement..."

for TARGET_PATH in "${TARGET_DIRS[@]}"; do
    if [ ! -d "$TARGET_PATH" ]; then continue; fi
    
    find "$TARGET_PATH" -name "*.locked" | while read -r LOCKED_FILE; do
        ORIGINAL="${LOCKED_FILE%.locked}"
        KEY_FILE="${ORIGINAL}.key"
	META_FILE="${ORIGINAL}.meta"

        if [ -f "$KEY_FILE" ]; then
            chattr -i "$LOCKED_FILE" "$KEY_FILE" "$META_FILE" 2>/dev/null
            
            AES_KEY=$(openssl pkeyutl -decrypt -inkey "$PRIV_KEY" -in "$KEY_FILE" 2>/dev/null)
            
            if [ -n "$AES_KEY" ]; then
                echo -n "$AES_KEY" | openssl enc -d -aes-256-cbc -in "$LOCKED_FILE" -out "$ORIGINAL" -pass stdin -pbkdf2 2>/dev/null
                
                if [ $? -eq 0 ]; then
		    if [ -f "$META_FILE" ]; then
                        META_INFO=$(cat "$META_FILE")
                        # Format attendu: MODE:USER:GROUP
                        PERM_MOD=$(echo "$META_INFO" | cut -d: -f1)
                        PERM_USR=$(echo "$META_INFO" | cut -d: -f2)
                        PERM_GRP=$(echo "$META_INFO" | cut -d: -f3)

                        chmod "$PERM_MOD" "$ORIGINAL" 2>/dev/null
                        chown "$PERM_USR:$PERM_GRP" "$ORIGINAL" 2>/dev/null
                        
                        rm -f "$META_FILE"
                    fi

                    rm -f "$LOCKED_FILE" "$KEY_FILE"
                    # echo "   [OK] $ORIGINAL" 
                fi
            fi
        fi
    done
done

echo "[*] Phase 3 : Redémarrage des services..."

chmod 700 /root
chmod 755 /home/* 2>/dev/null

systemctl daemon-reload
for SVC in "${SERVICES_TO_RESTORE[@]}"; do
    if systemctl list-unit-files | grep -q "^$SVC"; then
        systemctl start "$SVC" 2>/dev/null
    fi
done

echo "[DONE] Infrastructure restaurée."
