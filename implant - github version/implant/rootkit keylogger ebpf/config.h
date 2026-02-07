#ifndef CONFIG_H
#define CONFIG_H

// Taille max d'une capture (ne pas toucher)
#define MAX_DATA_SIZE 16

// La structure de l'événement envoyé par le kernel
struct event {
    int pid;
    int len;
    unsigned char data[MAX_DATA_SIZE];
};

#endif
