#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <stdint.h>
#include <iproute2/bpf_elf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define BUCKETS 10240

struct conn_s {
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t protocol;
};

struct bpf_elf_map flowsnoop_4_0 SEC("maps") = {
    .type           = BPF_MAP_TYPE_HASH,
    .size_key       = sizeof(struct conn_s),
    .size_value     = sizeof(uint64_t),
    .pinning        = PIN_GLOBAL_NS,
    .max_elem       = BUCKETS,
};

struct bpf_elf_map flowsnoop_4_1 SEC("maps") = {
    .type           = BPF_MAP_TYPE_HASH,
    .size_key       = sizeof(struct conn_s),
    .size_value     = sizeof(uint64_t),
    .pinning        = PIN_GLOBAL_NS,
    .max_elem       = BUCKETS,
};

struct conn6_s {
  uint8_t src_ip[16];
  uint8_t dst_ip[16];
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t protocol;
};

struct bpf_elf_map flowsnoop_6_0 SEC("maps") = {
    .type           = BPF_MAP_TYPE_HASH,
    .size_key       = sizeof(struct conn6_s),
    .size_value     = sizeof(uint64_t),
    .pinning        = PIN_GLOBAL_NS,
    .max_elem       = BUCKETS,
};

struct bpf_elf_map flowsnoop_6_1 SEC("maps") = {
    .type           = BPF_MAP_TYPE_HASH,
    .size_key       = sizeof(struct conn6_s),
    .size_value     = sizeof(uint64_t),
    .pinning        = PIN_GLOBAL_NS,
    .max_elem       = BUCKETS,
};

struct bpf_elf_map flowsnoop_switch SEC("maps") = {
    .type           = BPF_MAP_TYPE_ARRAY,
    .size_key       = sizeof(uint32_t),
    .size_value     = sizeof(uint32_t),
    .pinning        = PIN_GLOBAL_NS,
    .max_elem       = 1,
};


/*
 * Kudos https://mechpen.github.io/posts/2019-08-29-bpf-verifier/
 * for working out the correct sequence for the verifier.
 * Original comment:
 *
 * 2 things are done here to make the verifier happy:
 *
 *   - split offset into var_off and const_off
 *   - perform the 2nd check regardless of the 1st check
 */
#define ensure_header(skb, var_off, const_off, hdr)		\
({								\
	uint32_t len = const_off + sizeof(*hdr);		\
	void *data = (void *)(long)skb->data + var_off;		\
	void *data_end = (void *)(long)skb->data_end;		\
								\
	if (data + len > data_end)				\
		bpf_skb_pull_data(skb, var_off + len);		\
								\
	data = (void *)(long)skb->data + var_off;		\
	data_end = (void *)(long)skb->data_end;			\
	if (data + len > data_end)				\
		return TC_ACT_OK;				\
								\
	hdr = (void *)(data + const_off);			\
})


static __always_inline int ip_is_fragment(const struct iphdr *iph)
{
#define IP_MF (1 << 2)
#define IP_OFFSET (0x1fff << 3)
  return (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET)) != 0;
  return 0;
}

static __always_inline int ipv4_hdrlen(struct iphdr *ip4)
{
	return ip4->ihl * 4;
}

static __always_inline int account_data(struct __sk_buff *skb)
{
  struct ethhdr *eth;
  struct tcphdr *tcp;
  struct iphdr *iph;
  uint32_t hdrlen, var_off, const_off;
  uint32_t *sw;
  uint32_t zero = 0;
  uint64_t *oval = 0;
  uint64_t len = skb->len - sizeof(struct ethhdr);
  var_off = 0;
  const_off = 0;
  ensure_header(skb, var_off, const_off, eth);
  if (eth->h_proto != bpf_htons(ETH_P_IP))
    return TC_ACT_OK;
  const_off += ETH_HLEN;
  ensure_header(skb, var_off, const_off, iph);
  if (iph->version == 4) {
    struct conn_s conn = {};
    struct bpf_elf_map *conn_table = &flowsnoop_4_0;
    conn.src_ip = iph->saddr;
    conn.dst_ip = iph->daddr;
    conn.protocol = iph->protocol;
    if ((conn.protocol == 6 || conn.protocol == 17) && !ip_is_fragment(iph)) {
      hdrlen = ipv4_hdrlen(iph);
      var_off += hdrlen;
      ensure_header(skb, var_off, const_off, tcp);
      conn.src_port = tcp->source;
      conn.dst_port = tcp->dest;
    }
    sw = bpf_map_lookup_elem(&flowsnoop_switch, &zero);
    if (sw && *sw == 1) {
      conn_table = &flowsnoop_4_1;
    }
    oval = bpf_map_lookup_elem(conn_table, &conn);
    if (oval) {
      __sync_fetch_and_add(oval, len);
    } else {
      uint64_t nval = len;
      if (bpf_map_update_elem(conn_table, &conn, &nval, BPF_NOEXIST) == -1) {
	oval = bpf_map_lookup_elem(conn_table, &conn);
	if (oval)
	  __sync_fetch_and_add(oval, len);
      }
    }
  } // else if (iph->version == 6) {}
  return TC_ACT_OK;
}

SEC("ingress")
int tc_ingress(struct __sk_buff *skb)
{
    return account_data(skb);
}

SEC("egress")
int tc_egress(struct __sk_buff *skb)
{
    return account_data(skb);
}

char __license[] SEC("license") = "GPL";
