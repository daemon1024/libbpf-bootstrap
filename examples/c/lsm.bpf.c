#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define PATHLEN 256

struct output {
    u32 uid;
    char buf[PATHLEN];
};

SEC("lsm/bprm_creds_from_file")
int BPF_PROG(print_name, struct linux_binprm *bprm, int ret)
{
    char bl[] = "/bin/ls";
    struct output o;
    int len;    
    
    len = bpf_probe_read_str(o.buf, sizeof(o.buf), bprm->filename);
    
    if (len >  7) {
        if (o.buf[0] == bl[0] && o.buf[1] == bl[1] && o.buf[2] == bl[2] && o.buf[3] == bl[3] && o.buf[4] == bl[4] && o.buf[5] == bl[5] && o.buf[6] == bl[6] && o.buf[7] == bl[7] ){
            return -1;
        }
    }

    return 0;
}
