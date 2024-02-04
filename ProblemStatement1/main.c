#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

// Define a map for storing the configurable port number
struct bpf_map_def SEC("maps") port_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u16),
    .max_entries = 1,
};

SEC("socket")
int bpf_prog(struct __sk_buff *skb) {
    // Get the configurable port number from the map
    u32 key = 0;
    u16 *port = bpf_map_lookup_elem(&port_map, &key);

    if (!port) {
        // Default port if not configured
        return XDP_PASS;
    }

    // Check if the packet is TCP
    if (bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_proto), &skb->protocol, sizeof(skb->protocol)) == 0 &&
        ntohs(skb->protocol) == ETH_P_IP) {
        struct iphdr *ip = bpf_hdr_pointer(skb, 0);

        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)(ip + 1);

            // Check if the destination port matches the configured port
            if (ntohs(tcp->dest) == *port) {
                // Drop the packet
                return XDP_DROP;
            }
        }
    }

    // Pass the packet
    return XDP_PASS;
}
