#ifndef __INTERP_H__
#define __INTERP_H__

#include <stdint.h>
#include <linux/filter.h>

#define ARR_LEN(arr) ((sizeof(arr))/(sizeof((arr)[0])))

typedef struct {
    size_t size;
    const char* scapy_exp;
    uint8_t* buf;
} packet_t;

typedef int(bpf_interp_t)(struct sock_fprog* filter, packet_t* packet);
typedef void(bpf_batch_interp_t)(struct sock_fprog* filters, size_t n_filters, packet_t* packets, size_t n_packets, int** put_results);

void generic_nested_loop(bpf_interp_t interp, struct sock_fprog* filters, size_t n_filters, packet_t* packets, size_t n_packets, int** put_results) {
    for(int filter_idx = 0; filter_idx < n_filters; ++filter_idx) {
        for(int packet_idx = 0; packet_idx < n_packets; ++packet_idx) {
            put_results[filter_idx][packet_idx] = interp(&filters[filter_idx], &packets[packet_idx]);
        }
    }
}


#endif