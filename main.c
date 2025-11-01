#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

#include <pcap.h>
#include <stdlib.h>
#include <time.h>

#include "interp.h"
#include "data.h"

int pcap_interp(struct sock_fprog* filter, packet_t* packet) {
    struct pcap_pkthdr pak_hdr = {
        {0},
        packet->size,
        packet->size
    };
    return pcap_offline_filter((const struct bpf_program*)filter, &pak_hdr, packet->buf);
}

void nested_loop_pcap_interp(struct sock_fprog* filters, size_t n_filters, packet_t* packets, size_t n_packets, int** put_results) {
    generic_nested_loop(pcap_interp, filters, n_filters, packets, n_packets, put_results);
}

int** allocate_results_table() {
    int** results = NULL;
    results = malloc(sizeof(int*)*N_FILTERS);
    if(results == NULL) {
        exit(1);
    }
    for(int filter_idx = 0; filter_idx < N_FILTERS; ++filter_idx) {
        results[filter_idx] = malloc(sizeof(int)*N_PACKETS);
        if(results[filter_idx] == NULL) {
            exit(1);
        }
    }
    return results;
}

void print_results_table(int** results) {
    for(int filter_idx = 0; filter_idx < N_FILTERS; ++filter_idx) {
        for(int packet_idx = 0; packet_idx < N_PACKETS; ++packet_idx) {
            printf("%04x ", results[filter_idx][packet_idx]);
        }
        printf("\n");
    }
}

#define NUM_ITERS (1000000)

int main() {
    struct timespec start, stop;
    
    int** results = allocate_results_table();
    printf("Done allocating table\n");
    
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
    for(int i = 0; i < NUM_ITERS; ++i) {
        nested_loop_pcap_interp(all_filters, N_FILTERS, all_packets, N_PACKETS, results);
    }
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stop);
    double duration_ns = (stop.tv_sec - start.tv_sec) * 1e9 + (stop.tv_nsec - start.tv_nsec);
    printf("average processing time is %lf nanoseconds\n", duration_ns/(N_FILTERS * N_PACKETS * NUM_ITERS));

    // print_results_table(results);
    // printf("Done printing results\n");

    return 0;
}
