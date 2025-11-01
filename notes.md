https://docs.kernel.org/networking/filter.html

https://lwn.net/Articles/976317/

https://github.com/microsoft/bpf_performance

https://www.youtube.com/watch?v=UxnkdB2ftms

https://github.com/eunomia-bpf/bpf-benchmark


```bpf
00: ldh   [12]
01: jeq   #0x86dd        jt 2    jf 8
02: ldb   [20]
03: jeq   #0x6           jt 4    jf 19
04: ldh   [54]
05: jeq   #0x4d          jt 18   jf 6
06: ldh   [56]
07: jeq   #0x4d          jt 18   jf 19
08: jeq   #0x800         jt 9    jf 19
09: ldb   [23]
10: jeq   #0x6           jt 11   jf 19
11: ldh   [20]
12: jset  #0x1fff        jt 19   jf 13
13: ldxb  4*([14]&0xf)
14: ldh   [x + 14]
15: jeq   #0x4d          jt 18   jf 16
16: ldh   [x + 16]
17: jeq   #0x4d          jt 18   jf 19
18: ret   #262144
19: ret   #0
```

```
# --- Ethernet header ---
00/00: ldh   [12]                     # Load 16-bit EtherType field from Ethernet header
01/01: jeq   #0x86dd        jt 2 jf 8 # If EtherType == 0x86DD (IPv6), jump to IPv6 branch; else check if IPv4 (0x0800)

# --- IPv6 branch ---
02/02: ldb   [20]                     # Load IPv6 Next Header (protocol number)
03/03: jeq   #0x6           jt 4 jf 19# If protocol == 6 (TCP), go to IPv6 TCP port check, else reject (ret 0)
04/04: ldh   [54]                     # Load 16-bit field at offset 54 (TCP src port for IPv6)
05/05: jeq   #0x4d          jt 18 jf 6# If src port == 77 (0x4d), accept; else check dst port
06/06: ldh   [56]                     # Load 16-bit field at offset 56 (TCP dst port for IPv6)
07/07: jeq   #0x4d          jt 18 jf 19# If dst port == 77, accept; else reject

# --- IPv4 branch ---
08/08: jeq   #0x800         jt 9 jf 19# If EtherType == 0x0800 (IPv4), jump to IPv4 logic; else reject
09/09: ldb   [23]                     # Load IPv4 Protocol field (at offset 23)
0a/10: jeq   #0x6           jt 11 jf 19# If protocol == 6 (TCP), proceed; else reject
0b/11: ldh   [20]                     # Load IPv4 Flags/Fragment Offset field
0c/12: jset  #0x1fff        jt 19 jf 13# If any fragment bits set (not first fragment), reject
0d/13: ldxb  4*([14]&0xf)            # Compute IP header length (IHL * 4), store in X register
0e/14: ldh   [x + 14]                # Load TCP source port (IPv4)
0f/15: jeq   #0x4d          jt 18 jf 16# If src port == 77, accept; else check dst port
10/16: ldh   [x + 16]                # Load TCP destination port (IPv4)
11/17: jeq   #0x4d          jt 18 jf 19# If dst port == 77, accept; else reject

# --- Common return points ---
12/18: ret   #262144                 # Accept packet (snapshot length 262144 bytes)
13/19: ret   #0                      # Reject packet
```