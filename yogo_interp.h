#ifndef __YOGO_INTERP_H__
#define __YOGO_INTERP_H__

#include "interp.h"
#include <stdio.h>

void nested_loop_yogo_interp(struct sock_fprog* filters, size_t n_filters, packet_t* packets, size_t n_packets, int** put_results);

#endif