#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

SEC("filter")
int filter_packets(struct __sk_buff *skb) {
    // Parse Ethernet header
    struct ethhdr *eth = bpf_hdr(skb);
    if (eth->h_proto != htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // Parse IP header
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if (ip->saddr == htonl(0x7F000001)) {  // 127.0.0.1
        return XDP_DROP;
    }

    return XDP_PASS;
}
