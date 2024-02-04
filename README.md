# OverView

## Problem statement 1: Drop packets using eBPF
### To achieve this, we have used eBPF (extended Berkeley Packet Filter) with a BPF program attached to a socket. eBPF code that drops TCP packets on a specific port, with the port number made configurable from userspace:


## Problem statement 2: Drop packets only for a given process
### eBPF (extended Berkeley Packet Filter) code is typically written in C and then compiled into bytecode to be loaded into the Linux kernel. eBPF code that allows traffic only on a specific TCP port (4040) for a given process name ("myprocess") and drops all other traffic for that process.

