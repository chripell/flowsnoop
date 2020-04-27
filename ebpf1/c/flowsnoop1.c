#include <uapi/linux/ptrace.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct conn_s{
  u32 src_ip;
  u32 dst_ip;
  u16 src_port;
  u16 dst_port;
  u8 protocol;
};
BPF_HISTOGRAM(connections, struct conn_s, BUCKETS);

struct conn6_s{
  u8 src_ip[16];
  u8 dst_ip[16];
  u16 src_port;
  u16 dst_port;
  u8 protocol;
};
BPF_HISTOGRAM(connections6, struct conn6_s, BUCKETS);

static inline struct tcphdr *skb_to_tcphdr(const struct sk_buff *skb)
{
  // unstable API. verify logic in tcp_hdr() -> skb_transport_header().
  return (struct tcphdr *)(skb->head + skb->transport_header);
}

static inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb)
{
  // unstable API. verify logic in ip_hdr() -> skb_network_header().
  return (struct iphdr *)(skb->head + skb->network_header);
}

static inline struct ipv6hdr *skb_to_ipv6hdr(const struct sk_buff *skb)
{
  // unstable API. verify logic in ip_hdr() -> skb_network_header().
  return (struct ipv6hdr *)(skb->head + skb->network_header);
}

static int do_count4(struct sk_buff *skb, int len) {
  struct iphdr *ip = skb_to_iphdr(skb);
  unsigned char *pc = (unsigned char *) ip;
  struct conn_s conn = {};
  if ((pc[0] & 0xf0) != 0x40)	/* IPv4 only */
    return -1;
  conn.protocol = ip->protocol;
  conn.src_ip = ip->saddr;
  conn.dst_ip = ip->daddr;
  if (ip->protocol == 6 || ip->protocol == 17) { /* TCP and UDP have ports */
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    conn.src_port = tcp->source;
    conn.dst_port = tcp->dest;
  } else {
    conn.src_port = 0;
    conn.dst_port = 0;
  }
  connections.increment(conn, len);
  return 0;
}

static int do_count6(struct sk_buff *skb, int len) {
  struct ipv6hdr *ip = skb_to_ipv6hdr(skb);
  unsigned char *pc = (unsigned char *) ip;
  struct conn6_s conn = {};
  if ((pc[0] & 0xf0) != 0x60)	/* IPv6 only */
    return -1;
  /* TODO: check this, it is not correct in all cases. */
  conn.protocol = ip->nexthdr;
  bpf_probe_read(conn.src_ip, 16, &ip->saddr);
  bpf_probe_read(conn.dst_ip, 16, &ip->daddr);
  if (conn.protocol == 6 || conn.protocol == 17) { /* TCP and UDP have ports */
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    conn.src_port = tcp->source;
    conn.dst_port = tcp->dest;
  } else {
    conn.src_port = 0;
    conn.dst_port = 0;
  }
  connections6.increment(conn, len);
  return 0;
}

static int equal(char *src, char *dst, int n) {
  int i;
  for(i=0; i<n; i++)
    if (src[i] != dst[i])
      return 1;
  return 0;
}

static void do_count(struct sk_buff *skb, int len, char *dev) {
  DEVS;
  if (CMPS) /* connected by && */
    return;
  if (0 == do_count4(skb, len))
    return;
  if (0 == do_count6(skb, len))
    return;
}

TRACEPOINT_PROBE(net, netif_receive_skb) {
  // args is from /sys/kernel/debug/tracing/events/net/netif_rx/format
  char dev[16];
  struct sk_buff *skb = (struct sk_buff *) args->skbaddr;
  TP_DATA_LOC_READ_CONST(dev, name, 16);
  do_count(skb, args->len, dev);
  return 0;
};

TRACEPOINT_PROBE(net, net_dev_start_xmit) {
  // args is from /sys/kernel/debug/tracing/events/net/net_dev_start_xmit/format
  char dev[16];
  struct sk_buff *skb = (struct sk_buff *) args->skbaddr;
  TP_DATA_LOC_READ_CONST(dev, name, 16);
  do_count(skb, args->len - args->network_offset, dev);
  return 0;
};
