import struct
import sys
import os
import re
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# --- CONFIGURATION ---
PRIV_KEY_PATH = "private_key.pem"
DEFAULT_LOG_FILE = ".journald-audit-cache.dat"

class VT100Parser:
    """
    Simulateur de terminal pour maintenir l'état du buffer.
    """
    def __init__(self):
        self.buffer = []
        self.cursor = 0

    def add_char(self, char):
        while len(self.buffer) < self.cursor:
            self.buffer.append(' ')
        
        if len(self.buffer) == self.cursor:
            self.buffer.append(char)
        else:
            self.buffer[self.cursor] = char
        self.cursor += 1

    def backspace(self):
        if self.cursor > 0:
            self.cursor -= 1

    def clear_line_from_cursor(self):
        self.buffer = self.buffer[:self.cursor]

    def get_text(self):
        return "".join(self.buffer)

    def reset(self):
        self.buffer = []
        self.cursor = 0

def clean_terminal_stream(text: str) -> str:
    """
    Nettoyeur intelligent avec réparation des séquences ESC manquantes.
    """
    ESC = chr(27) # On définit ESC proprement pour éviter les erreurs de regex

    # 0) Réparer les CSI "mutilées" (quand ESC a disparu dans les logs)
    # On cherche un crochet '[' suivi de params, non précédé par ESC.
    try:
        pattern = r'(?<!\x1b)\[' + r'([0-9;?]*[A-Za-z])'
        replacement = ESC + r'[\1'
        text = re.sub(pattern, replacement, text)
    except Exception:
        # Si la regex plante sur certaines versions python, on ignore la réparation
        pass

    # 1) Virer les séquences de "bracketed paste"
    text = re.sub(r'\x1b\[\?2004[hl]', '', text)

    parser = VT100Parser()
    final_output = []

    # ÉTATS DU PARSER
    STATE_NORMAL = 0
    STATE_ESC = 1
    STATE_CSI = 2
    STATE_OSC = 3 

    state = STATE_NORMAL
    csi_params = ""

    i = 0
    while i < len(text):
        ch = text[i]

        # Support CSI 0x9b (single-byte CSI)
        if state == STATE_NORMAL and ch == '\x9b':
            state = STATE_CSI
            csi_params = ""
            i += 1
            continue

        if state == STATE_NORMAL:
            if ch == ESC:
                state = STATE_ESC
            elif ch in ('\x08', '\x7f'):  # Backspace
                parser.backspace()
            elif ch == '\r':              # Carriage Return
                parser.cursor = 0
            elif ch == '\n':              # New Line
                final_output.append(parser.get_text())
                parser.reset()
            else:
                # Gestion Tabulation
                if ch == '\t':
                    for _ in range(4): parser.add_char(' ')
                # Caractères imprimables
                elif ord(ch) >= 32:
                    parser.add_char(ch)

        elif state == STATE_ESC:
            if ch == '[':
                state = STATE_CSI
                csi_params = ""
            elif ch == ']':
                state = STATE_OSC
            else:
                state = STATE_NORMAL

        elif state == STATE_OSC:
            if ch == '\x07': # BEL
                state = STATE_NORMAL
            elif ch == ESC and i + 1 < len(text) and text[i + 1] == '\\':
                state = STATE_NORMAL
                i += 1
            else:
                # On avance pour éviter une boucle infinie si l'OSC est mal formé
                i += 1 
                continue

        elif state == STATE_CSI:
            # CORRECTION CRITIQUE : On vérifie strictement les chiffres ASCII '0'-'9'
            # Cela empêche les caractères comme '²' de planter le script
            if ('0' <= ch <= '9') or ch in (';', '?'):
                csi_params += ch
            else:
                cmd = ch
                nums = [p for p in csi_params.replace('?', '').split(';') if p != '']
                
                n = 1
                if nums and nums[0].isdigit():
                    try:
                        n = int(nums[0])
                    except ValueError:
                        n = 1 # Fallback safe

                if cmd == 'K': # Erase Line (Correction fautes de frappe)
                    parser.clear_line_from_cursor()
                elif cmd == 'D': # Cursor Left
                    for _ in range(n): parser.backspace()
                elif cmd == 'C': # Cursor Right
                    parser.cursor += n
                elif cmd in ('H', 'f'):
                    col = 1
                    if len(nums) >= 2 and nums[1].isdigit():
                        try:
                            col = int(nums[1])
                        except ValueError:
                            col = 1
                    parser.cursor = max(0, col - 1)
                
                state = STATE_NORMAL

        i += 1

    if parser.buffer:
        final_output.append(parser.get_text())

    return "\n".join(final_output)

def decrypt():
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = DEFAULT_LOG_FILE

    if not os.path.exists(log_file):
        print(f"[-] Fichier '{log_file}' introuvable.")
        return

    try:
        if not os.path.exists(PRIV_KEY_PATH):
            print(f"[-] Clé privée '{PRIV_KEY_PATH}' introuvable.")
            return

        with open(PRIV_KEY_PATH, "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None)
            
        with open(log_file, "rb") as f:
            magic = f.read(6)
            if magic != b"CHAMv9":
                print(f"[-] Erreur Header: Attendu CHAMv9, reçu {magic}")

            enc_len = struct.unpack("<I", f.read(4))[0]
            enc_key = f.read(enc_len)
            
            session_key = private_key.decrypt(
                enc_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None)
            )
            
            session_nonce = f.read(12)
            print("[+] Session déchiffrée. Rejeu VT100 en cours...\n")
            
            full_data = b""

            while True:
                ctr_data = f.read(4)
                if not ctr_data: break
                chunk_len = struct.unpack("<I", f.read(4))[0]
                ciphertext = f.read(chunk_len)
                
                iv = session_nonce + ctr_data
                cipher = Cipher(algorithms.AES(session_key), modes.CTR(iv))
                decryptor = cipher.decryptor()
                full_data += decryptor.update(ciphertext) + decryptor.finalize()
            
            # Utilisation de Latin-1 pour garder les octets intacts
            raw_text = full_data.decode('latin-1', errors='strict')
            
            # Nettoyage
            clean_text = clean_terminal_stream(raw_text)
            
            print("================== SESSION RECONSTITUÉE ==================")
            print(clean_text)
            print("\n==========================================================")

    except Exception as e:
        print(f"[-] Erreur : {e}")

if __name__ == "__main__":
    decrypt()
