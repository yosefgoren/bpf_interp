#!/usr/bin/python3

import subprocess
import json
import click
import dataclasses
from scapy.all import *

def get_prefix_c() -> str:
    return """\
#ifdef __DATA_H__
#error "this file must not be included more than once!"
#else
#define __DATA_H__
#include "interp.h"
"""

def tcpdump_compile(bpf: str, flags: str) -> list[str]:
    try:
        return list(subprocess.check_output(f"tcpdump {flags} {bpf}", shell=True, stderr=subprocess.DEVNULL).decode().splitlines())
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to compile '{bpf}'") from e

def compile_bpf_to_c(bpf: str) -> str:
    bin_lines = tcpdump_compile(bpf, "-dd")
    asm_lines = tcpdump_compile(bpf, "-d")
    return "\n".join([f"\t{bin_line} //{asm_line}" for bin_line, asm_line in zip(bin_lines, asm_lines)])

def get_bpf_c_decleration(bpf: str, var_name: str) -> str:
    return 

@dataclasses.dataclass
class FilterGeneratorC:
    bpf: str
    idx: int
    
    def __post_init__(self):
        self.var_name: str = f"filter_{self.idx}_ops"
        self.c_impl: str = f"struct sock_filter {self.var_name}[] = //{self.bpf}" + "\n{\n" + compile_bpf_to_c(self.bpf) + "\n};"
        self.c_fprog_entry: str = "{ " + f"ARR_LEN({self.var_name}), {self.var_name}" + " },"


def gen_filters_c() -> str:
    filters = json.load(open("filters.json", 'r'))
    generators = [FilterGeneratorC(bpf, idx) for idx, bpf in enumerate(filters)]
    
    filter_impls = "\n".join([g.c_impl for g in generators])
    
    all_filters_content = "\n".join([f"\t{g.c_fprog_entry}" for g in generators])
    all_filters_decl = "struct sock_fprog all_filters[] = {\n" + all_filters_content + "\n};"

    return filter_impls + "\n\n" + all_filters_decl

@dataclasses.dataclass
class PacketGeneratorC:
    scapy_exp: str
    idx: int

    def __post_init__(self):
        self.var_name: str = f"packet_{self.idx}_data"
        self.scapy_pkt = eval(self.scapy_exp)
        self.bytes = bytes(self.scapy_pkt)
        self.c_impl = f"uint8_t {self.var_name}[] = //{self.scapy_exp}\n" "\t{ " + ", ".join([hex(b) for b in self.bytes]) + " };\n"
        self.arr_entry = "{ " + f"sizeof({self.var_name}), {self.var_name}" + " },"


def gen_packets_c() -> str:
    packets = json.load(open("packets.json", 'r'))
    generators = [PacketGeneratorC(p, idx) for idx, p in enumerate(packets)]
    
    packets_impls = "\n".join([g.c_impl for g in generators])

    all_packets_content = "\n".join([f"\t{g.arr_entry}" for g in generators])
    all_packets_decl = "packet_t all_packets[] = {\n" + all_packets_content + "\n};"

    return packets_impls + "\n\n" + all_packets_decl

def get_suffix_c() -> str:
    return """\
#define N_FILTERS (ARR_LEN(all_filters))
#define N_PACKETS (ARR_LEN(all_packets))
#endif
"""

@click.command("gen")
def gen():
    prefix_c = get_prefix_c()
    filters_c = gen_filters_c()
    packets_c = gen_packets_c()
    suffix_c = get_suffix_c()
    
    code = "\n".join([prefix_c, filters_c, packets_c, suffix_c])
    print(code)

if __name__ == "__main__":
    gen()