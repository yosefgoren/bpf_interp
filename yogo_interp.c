
struct bpf_vm_state {
    uint32_t pc;
    uint32_t A;
    uint32_t X;
    uint32_t M[16];
};

int check_filter(struct sock_fprog* filter, packet_t* packet) {
    struct bpf_vm_state state = {0};

    for(; state.pc < filter->len; ++state.pc) {
        struct sock_filter* instr = &filter->filter[state.pc];
        if(BPF_CLASS(instr->code) == BPF_RET) {
            if(BPF_SRC(instr->code) == BPF_K) {
                return instr->k;
            } else {
                return state.A;
            }
        }
    }
    return 0;
}
