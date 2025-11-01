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
#include "yogo_interp.h"
#include "data.h"
#include "ansi_colors.h"

int pcap_interp(struct sock_fprog* filter, packet_t* packet) {
    struct pcap_pkthdr pak_hdr = {
        {0},
        packet->size,
        packet->size
    };
    return pcap_offline_filter((const struct bpf_program*)filter, &pak_hdr, packet->buf);
}

DECLARE_NESTED_LOOP_INTERP(pcap_interp)

int always_zero_interp(struct sock_fprog* filter, packet_t* packet) {
    return 0;
}

DECLARE_NESTED_LOOP_INTERP(always_zero_interp)

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

#define DROP_STR ANSI_BYELLOW_WRAP("DROP")
#define PASS_STR ANSI_BCYAN_WRAP("PASS")

const char* get_packet_status_msg(int result) {
    return result == 0 ? DROP_STR : PASS_STR;
}

void print_results_tables(int** expected_results, int** gotten_results) {
    for(int filter_idx = 0; filter_idx < N_FILTERS; ++filter_idx) {
        printf("%s%s%s:\n", ANSI_BBLUE_RAW, filter_expressions[filter_idx], ANSI_RESET);
        for(int packet_idx = 0; packet_idx < N_PACKETS; ++packet_idx) {
            int expected_res = expected_results[filter_idx][packet_idx];
            int gotten_res = gotten_results[filter_idx][packet_idx];

            const char* message = (expected_res == gotten_res) ? ANSI_BGREEN_WRAP("SAME") : ANSI_BRED_WRAP("DIFF");
            printf("\t%s %s/%s: %s\n", message, get_packet_status_msg(expected_res), get_packet_status_msg(gotten_res), all_packets[packet_idx].scapy_exp);
        }
        printf("\n");
    }
}

#define NUM_ITERS (100000)

void run_btach_interp_on_all(bpf_batch_interp_t interp, int** put_results) {
    struct timespec start, stop;
    
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
    for(int i = 0; i < NUM_ITERS; ++i) {
        interp(all_filters, N_FILTERS, all_packets, N_PACKETS, put_results);
    }
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stop);
    double duration_ns = (stop.tv_sec - start.tv_sec) * 1e9 + (stop.tv_nsec - start.tv_nsec);
    printf("average processing time is %lf nanoseconds\n", duration_ns/(N_FILTERS * N_PACKETS * NUM_ITERS));
}

int main() {
    int** pcap_results = allocate_results_table();
    int** yogo_results = allocate_results_table();
    printf("Done allocating tables\n");
    
    run_btach_interp_on_all(nested_loop_pcap_interp, pcap_results);
    run_btach_interp_on_all(nested_loop_yogo_interp, yogo_results);

    print_results_tables(pcap_results, yogo_results);
    printf("Done printing results\n");

    return 0;
}
