**This is not an officially supported Google product**

# Flowsnoop

Flowsnoop is a tool to inspect network flows. Its architecture allows
different producers and consumers to be matched. You can get a list of
all the available options by passing the `--help` flag. This tool
focus on estimating data exchanged on ISO/OSI levels from 3 on so
it doesn't (or at least it tries to not) count level 2 overhead.

It is currently tested on x86_64 and aarch64 (the latter a Raspberry Pi4
in bridge mode).

# Producers

## ebpf3

`ebpf3` hooks into tc classifier to get the information about
flows. It is surprisingly different from `ebfp2` because the loader is
different. Also, the `sk_buff` structure has less information and
requires a more complicated parser.

The Go part uses the library
[goebpf](https://github.com/dropbox/goebpf) so it doesn't need to
interface directly with `libepf.h` (it is pure Go, not
cgo). Otherwise, the map handling logic is very similar to `ebpf2`,
with double buffering.

This is the best producer to use because it assures the sk_buffs are
linearized.

## ebpf2

`ebpf2` uses *CO-RE libbpf* library and so has no external
dependencies but `libbpf.so` and a kernel supporting eBPF for
tracepoints. For simplicity, some generated files are included in the
git repository (although the targets for generating them are in the
`Makefile`:

* `vmlinux.h` has the BTF information dumped from the kernel. It needs
  `bpftool` and a fairly new kernel (5.6 or later) with BTF support
  compiled in.
  
* The *skeleton* file, which embodies the compiled code and the
  interface in C. It needs `clang` and `bpftool` to be generated.
  
I *think* this version correctly handles concurrency:

* The eBPF part uses the atomicity of `__sync_fetch_and_add` and
  `bpf_map_update_elem` to avoid races by multiple CPUs.
  
* The reading of maps is based on 2 separate maps for each IP
  protocol, i.e. uses double buffering. While a map is read to user
  level, another one is used to store data in-kernel.

## ebpf1

This is a simple but very efficient eBPF based producer. Currently it
uses only one map so it might loss packets during reading. It will be
upgraded to a double buffered one.

## afp

`afp` uses the `gopacket` library to capture packets using a mmap-ed
`AF_PACKET` socket. It is more resource hungry but better tested.

# Consumers

## showflows

It simply prints all the captured network flows.

## topsites

`topsites` shows the most active traffic sources and destinations.

## sqlflows

`sqlflows` stores flows information into a sqlite3 data base.



