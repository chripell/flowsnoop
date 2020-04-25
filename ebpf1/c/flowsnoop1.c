#include <uapi/linux/ptrace.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/ip.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define LOCALHOST ((1<<24) + 127)

struct conn_s{
  u32 src_ip;
  u32 dst_ip;
  u16 src_port;
  u16 dst_port;
  u8 protocol;
};
BPF_HISTOGRAM(connections, struct conn_s, 16384);

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

static void do_count(struct sk_buff *skb) {
  struct iphdr *ip = skb_to_iphdr(skb);
  unsigned char *pc = (unsigned char *) ip;
  struct conn_s conn = {};
  int len = skb->len;
  if ((pc[0] & 0xf0) != 0x40	/* IPv4 only */
      || (ip->protocol != 6 && ip->protocol != 17) /* UDP and TCP */
      || ip->saddr == LOCALHOST || ip->daddr == LOCALHOST /* Ignore localhost */
      )
    return;
  conn.protocol = ip->protocol;
  conn.src_ip = ip->saddr;
  conn.dst_ip = ip->daddr;
  struct tcphdr *tcp = skb_to_tcphdr(skb);
  conn.src_port = tcp->source;
  conn.dst_port = tcp->dest;
  // TODO: check skb->data_len != 0.
  connections.increment(conn, len);
  // For debugging
  // bpf_trace_printk("%x %d\n", pc[0], ip->protocol);
}

TRACEPOINT_PROBE(net, netif_receive_skb) {
  // args is from /sys/kernel/debug/tracing/events/net/netif_rx/format
  struct sk_buff *skb = (struct sk_buff *) args->skbaddr;
  do_count(skb);
  return 0;
};

TRACEPOINT_PROBE(net, net_dev_start_xmit) {
  // args is from /sys/kernel/debug/tracing/events/net/net_dev_start_xmit/format
  struct sk_buff *skb = (struct sk_buff *) args->skbaddr;
  do_count(skb);
  return 0;
};
