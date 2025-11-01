#include <sys/types.h>
#include <stdbool.h>

#include "yogo_interp.h"
#include "pcap/bpf.h"

struct bpf_vm_state {
    uint32_t pc;
    uint32_t A;
    uint32_t X;
    uint32_t M[16];
};

static inline void assign_at_code_size(uint16_t code, void* dst, void* src) {
    switch (BPF_SIZE(code))
    {
    case BPF_W:
        *(uint32_t*)dst = *(uint32_t*)src;
        break;
    case BPF_H:
        *(uint16_t*)dst = *(uint16_t*)src;
        break;
    case BPF_B:
        *(uint8_t*)dst = *(uint8_t*)src;
        break;
    }
}

int yogo_interp(struct sock_fprog* filter, packet_t* packet) {
    struct bpf_vm_state state = {0};
    uint8_t* buf = packet->buf;
    uint32_t buflen = (uint32_t)packet->size;


    for(; state.pc < filter->len; ++state.pc) {
        struct sock_filter* instr = &filter->filter[state.pc];
        uint16_t code = instr->code;
        uint32_t K = instr->k;
        
        //switch-scope variables:
        uint32_t value = 0;
        uint32_t cmp_val = 0;
        bool cmp_res = false;
        
        switch(BPF_CLASS(code)) {
        case BPF_LD:
        case BPF_LDX:
            uint32_t* target = (BPF_CLASS(code) == BPF_LD) ? &state.A : &state.X;
            
            switch (BPF_MODE(code)) {
            case BPF_IMM://AM4
                *target = K;
                break;
            case BPF_ABS://AM1
                assign_at_code_size(code, target, buf+K);
                break;
            case BPF_IND://AM2
                assign_at_code_size(code, target, buf+state.X+K);
                break;
            case BPF_MEM://AM3
                *target = state.M[K];
                break;
            case BPF_LEN://AM12
                *target = buflen;
                break;
            case BPF_MSH://AM5
                break;
            }
            break;
        
        case BPF_ST:
        case BPF_STX:
            value = (BPF_CLASS(code) == BPF_ST) ? state.A : state.X;
            state.M[K] = value;
            break;
        
        case BPF_ALU:
            value = (BPF_MODE(code) == BPF_IMM) ? K : state.X; //AM4 : AM0
            switch(BPF_OP(code)) {
                case BPF_ADD:
                    state.A += value;
                    break;
                case BPF_SUB:
                    state.A -= value;
                    break;
                case BPF_MUL:
                    state.A *= value;
                    break;
                case BPF_DIV:
                    state.A /= value;
                    break;
                case BPF_OR:
                    state.A |= value;
                    break;
                case BPF_AND:
                    state.A &= value;
                    break;
                case BPF_LSH:
                    state.A <<= value;
                    break;
                case BPF_RSH:
                    state.A >>= value;
                    break;
                case BPF_NEG:
                    state.A = !state.A;
                    break;
                case BPF_MOD:
                    state.A %= state.A;
                    break;
                case BPF_XOR:
                    state.A ^= state.A;
                    break;
            }
            break;
        
        case BPF_JMP:
            if(BPF_OP(code) == BPF_JA) {
                state.pc += K;
            } else {
                cmp_val = (BPF_SRC(code) == BPF_K) ? K : state.X; //AM9 : AM10
                cmp_res = false;
                switch(BPF_OP(code)) {
                case BPF_JEQ:
                    cmp_res = (state.A == cmp_val);
                    break;
                case BPF_JGT:
                    cmp_res = (state.A > cmp_val);
                    break;
                case BPF_JGE:
                    cmp_res = (state.A >= cmp_val);
                    break;
                case BPF_JSET:
                    cmp_res = (state.A & cmp_val);
                    break;
                }
                state.pc += cmp_res ? instr->jt : instr->jf;
            }
            break;
        
        case BPF_RET:
            return (BPF_RVAL(code) == BPF_A) ? state.A : K; //AM11 : AM4
            
        case BPF_MISC:
            if(BPF_MISCOP(code) == BPF_TAX) {
                state.X = state.A;
            } else {
                state.A = state.X;
            }
            break;
        }
    }
    return 0;
}

DECLARE_NESTED_LOOP_INTERP(yogo_interp)
