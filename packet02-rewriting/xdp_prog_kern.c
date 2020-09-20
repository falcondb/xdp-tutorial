/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"

/* Defines xdp_stats_map */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

#define FAKEDVID 102

#define bpf_printk(fmt, ...)                                    \
({                                                              \
	char ____fmt[] = fmt;                                   \
	bpf_trace_printk(____fmt, sizeof(____fmt),              \
                         ##__VA_ARGS__);                        \
})

/* Pops the outermost VLAN tag off the packet. Returns the popped VLAN ID on
 * success or -1 on failure.
 */
static __always_inline int vlan_tag_pop(struct xdp_md *ctx, struct ethhdr *eth)
{
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr eth_cpy;
	struct vlan_hdr *vlh;
	__be16 h_proto;

	int vlid = -1;

	/* Check if there is a vlan tag to pop */
	if ( eth->h_proto != bpf_ntohs(ETH_P_8021Q) &&
	     eth->h_proto != bpf_ntohs(ETH_P_8021AD))
	     return -1;

	/* Still need to do bounds checking */
    if (eth + 1 > data_end)
        return -1;

    vlh = (struct vlan_hdr*) (eth + 1);
    if (vlh + 1 > data_end)
        return 1;

	/* Save vlan ID for returning, h_proto for updating Ethernet header */
    vlid = bpf_ntohs(vlh->h_vlan_TCI);
    h_proto = vlh->h_vlan_encapsulated_proto;

	/* Make a copy of the outer Ethernet header before we cut it off */
    __builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));

	/* Actually adjust the head pointer */
    if (bpf_xdp_adjust_head(ctx, (int)sizeof(*vlh)))
        return -1;
	/* Need to re-evaluate data *and* data_end and do new bounds checking
	 * after adjusting head
	 */
	eth = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

	if (eth + 1 > data_end)
		return -1;

	/* Copy back the old Ethernet header and update the proto type */
    __builtin_memcpy(eth, &eth_cpy, sizeof(*eth));
    eth->h_proto = h_proto;

	return vlid;
}

/* Pushes a new VLAN tag after the Ethernet header. Returns 0 on success,
 * -1 on failure.
 */
static __always_inline int vlan_tag_push(struct xdp_md *ctx,
					 struct ethhdr *eth, int vlid)
{
	struct vlan_hdr vlh;
	struct ethhdr ehdr;
	__be16 eth_type = eth->h_proto;

	if (eth_type == bpf_htons(ETH_P_IP) || eth_type == bpf_htons(ETH_P_IPV6))
	{
	    __builtin_memcpy(&ehdr, eth, sizeof(*eth));
	    if (bpf_xdp_adjust_head(ctx, -(int)sizeof(vlh)))
	        return -1;

	    if (ctx->data + sizeof(ehdr) + sizeof(vlh) > ctx->data_end)
	        return -1;

        ehdr.h_proto = bpf_htons(ETH_P_8021Q);
        __builtin_memcpy((void *)(long)ctx->data, &ehdr, sizeof(ehdr));
        vlh.h_vlan_TCI = bpf_htons(vlid);
        vlh.h_vlan_encapsulated_proto = eth_type;

        if (ctx->data + sizeof(ehdr) + sizeof(vlh) > ctx->data_end)
            return -1;
	    __builtin_memcpy((void *)(long)ctx->data + sizeof(ehdr), &vlh, sizeof(vlh));
	}

	return 0;
}

/* Implement assignment 1 in this section */
SEC("xdp_port_rewrite")
int xdp_patch_ports_func(struct xdp_md *ctx)
{
	int action = XDP_PASS;
	int eth_type, ip_type = 0;
	struct ethhdr *eth;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	struct udphdr *udphdr;
	struct tcphdr *tcphdr;
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh = { .pos = data };

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0) {
	     bpf_printk("Unknown Eth type: %hu\n", eth_type);
		action = XDP_ABORTED;
		goto out;
	}

	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
	} else {
	    bpf_printk("Unknown Eth type: %hu\n", eth_type);
		action = XDP_ABORTED;
		goto out;
	}

	if (ip_type == IPPROTO_UDP) {
		if (parse_udphdr(&nh, data_end, &udphdr) < 0) {
			action = XDP_ABORTED;
			goto out;
		}
		udphdr->dest = bpf_htons(bpf_ntohs(udphdr->dest) - 1);
	} else if (ip_type == IPPROTO_TCP) {
		if (parse_tcphdr(&nh, data_end, &tcphdr) < 0) {
			action = XDP_ABORTED;
			goto out;
		}

		tcphdr->dest = bpf_htons(bpf_ntohs(tcphdr->dest) - 1);
		action = XDP_PASS;
		goto out;
	} else {
        action = XDP_ABORTED;
        goto out;
	}

out:
	return xdp_stats_record_action(ctx, action);
}

/* VLAN swapper; will pop outermost VLAN tag if it exists, otherwise push a new
 * one with ID 1. Use this for assignments 2 and 3.
 */
SEC("xdp_vlan_swap")
int xdp_vlan_swap_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;
	nh.pos = data;

	struct ethhdr *eth;
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type < 0)
		return XDP_PASS;

	/* Assignment 2 and 3 will implement these. For now they do nothing */
	if (proto_is_vlan(eth->h_proto))
		vlan_tag_pop(ctx, eth);
	else
		vlan_tag_push(ctx, eth, FAKEDVID);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
