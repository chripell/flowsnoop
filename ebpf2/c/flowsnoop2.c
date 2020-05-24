#include "vmlinux.h"   /* all kernel types */
#include <bpf/bpf_helpers.h>       /* most used helpers: SEC, __always_inline, etc */
#include <bpf/bpf_core_read.h>     /* for BPF CO-RE helpers */
#include <bpf/bpf_tracing.h>       /* for getting kprobe arguments */

#define TP_DATA_LOC_READ_CONST(dst, field, length)                        \
        do {                                                              \
            unsigned short __offset = ctx->__data_loc_##field & 0xFFFF;   \
            bpf_probe_read((void *)dst, length, (char *)ctx + __offset); \
        } while (0);

const volatile char targ_iface[15] = {0,};

struct conn_s{
  u32 src_ip;
  u32 dst_ip;
  u16 src_port;
  u16 dst_port;
  u8 protocol;
};
struct connections_s {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct conn_s);
    __type(value, u64);
} connections SEC(".maps");

struct conn6_s{
  u8 src_ip[16];
  u8 dst_ip[16];
  u16 src_port;
  u16 dst_port;
  u8 protocol;
};
struct connections6_s {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct conn6_s);
    __type(value, u64);
} connections6 SEC(".maps");

static int is_equal(char *src, char *dst, int n) {
  int i;
  for(i=0; i<n; i++) {
    if (src[i] != dst[i])
      return 1;
    if (src[i] == '\0')
      return 0;
  }
  return 0;
}

static inline struct tcphdr *skb_to_tcphdr(const struct sk_buff *skb)
{
  return (struct tcphdr *)(BPF_CORE_READ(skb, head) +
			   BPF_CORE_READ(skb, transport_header));
}

static inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb)
{
  return (struct iphdr *)(BPF_CORE_READ(skb, head) +
			  BPF_CORE_READ(skb, network_header));
}

static inline struct ipv6hdr *skb_to_ipv6hdr(const struct sk_buff *skb)
{
  return (struct ipv6hdr *)(BPF_CORE_READ(skb, head) +
			  BPF_CORE_READ(skb, network_header));
}

static int do_count4(struct sk_buff *skb, int len) {
  struct iphdr *ip = skb_to_iphdr(skb);
  struct conn_s conn = {};
  u64 *oval = 0;
  u64 nval = 0;
  u8 version;
  bpf_probe_read(&version, 1, ip);
  if ((version & 0xf0) != 0x40)	/* IPv4 only */
    return -1;
  BPF_CORE_READ_INTO(&conn.protocol, ip, protocol);
  BPF_CORE_READ_INTO(&conn.src_ip, ip, saddr);
  BPF_CORE_READ_INTO(&conn.dst_ip, ip, daddr);
  if ((conn.protocol == 6 || conn.protocol == 17) &&
      BPF_CORE_READ(skb, transport_header) != 0) {
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    BPF_CORE_READ_INTO(&conn.src_port, tcp, source);
    BPF_CORE_READ_INTO(&conn.dst_port, tcp, dest);
  }
  oval = bpf_map_lookup_elem(&connections, &conn);
  if (oval)
    *oval += len;
  else {
    u64 nval = len;
    bpf_map_update_elem(&connections, &conn, &nval, 0);
  }
  return 0;
}

static int do_count6(struct sk_buff *skb, int len) {
  struct ipv6hdr *ip = skb_to_ipv6hdr(skb);
  struct conn6_s conn = {};
  u64 *oval = 0;
  u64 nval = 0;
  u8 version;
  bpf_probe_read(&version, 1, ip);
  if ((version & 0xf0) != 0x60)	/* IPv6 only */
    return -1;
  /* TODO: check this, it is not correct in all cases. */
  BPF_CORE_READ_INTO(&conn.protocol, ip, nexthdr);
  bpf_probe_read(conn.src_ip, 16, &ip->saddr);
  bpf_probe_read(conn.dst_ip, 16, &ip->daddr);
  if ((conn.protocol == 6 || conn.protocol == 17) &&
      BPF_CORE_READ(skb, transport_header) != 0) {
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    BPF_CORE_READ_INTO(&conn.src_port, tcp, source);
    BPF_CORE_READ_INTO(&conn.dst_port, tcp, dest);
  }
  oval = bpf_map_lookup_elem(&connections6, &conn);
  if (oval)
    *oval += len;
  else {
    u64 nval = len;
    bpf_map_update_elem(&connections6, &conn, &nval, 0);
  }
  return 0;
}

static __always_inline void do_count(struct sk_buff *skb, int len, char *dev) {
  if (!is_equal(dev, (char *)targ_iface, 16))
    return;
  if (0 == BPF_CORE_READ(skb,network_header))
    return;
  if (0 == do_count4(skb, len))
    return;
  if (0 == do_count6(skb, len))
    return;
}

SEC("tracepoint/net/netif_receive_skb")
int tracepoint__net_netif_receive_skb(struct trace_event_raw_net_dev_template *ctx) {
  char dev[16] = {0,};
  struct sk_buff *skb = (struct sk_buff *) ctx->skbaddr;
  TP_DATA_LOC_READ_CONST(dev, name, 16);
  do_count(skb, ctx->len, dev);
  return 0;
}

SEC("tracepoint/net/net_dev_start_xmit")
int tracepoint__net_net_dev_start_xmit(struct trace_event_raw_net_dev_start_xmit *ctx) {
  char dev[16] = {0,};
  struct sk_buff *skb = (struct sk_buff *) ctx->skbaddr;
  TP_DATA_LOC_READ_CONST(dev, name, 16);
  do_count(skb, ctx->len, dev);
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
