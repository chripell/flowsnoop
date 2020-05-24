# Flowsnoop

Flowsnoop is a tool to inspect network flows. Its architecture allows
different producers and consumers to be matched. You can get a list of
all the available options by passing the `--help` flag. This tool
focus on estimating data exchanged on ISO/OSI levels from 3 on so
it doesn't (or at least it tries to not) count level 2 overhead.

It is currently tested on x86_64 and aarch64 (the latter a Raspberry Pi4
in bridge mode).

# Producers

## ebpf1

This is a simple but very efficient eBPF based producer. Currently it
uses only one map so it might loss packets during reading. It will be
upgraded to a double buffered one.

## afp

`afp` uses the `gopacket` library to capture packets using a mmap-ed
`AF_PACKET` socket. It is more resource hungry but better tested.

## ebpf2

needs libbpf-0.0.8, bpftool, kernel with BTF

# Consumers

I plan to add a SQLite based consumer for long term storage of flow
information.

## showflows

It simply prints all the captured network flows.

## topsites

`topsites` shows the most active traffic sources and destinations.




