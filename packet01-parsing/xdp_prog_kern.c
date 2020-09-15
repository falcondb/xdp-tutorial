/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/icmpv6.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
/* Defines xdp_stats_map from packet04 */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

/* NOTICE: Re-defining VLAN header levels to parse */
#define VLAN_MAX_DEPTH 10
//#include "../common/parsing_helpers.h"
/*
 * NOTICE: Copied over parts of ../common/parsing_helpers.h
 *         to make it easier to point out compiler optimizations
 */

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

static __always_inline int proto_is_vlan(__u16 h_proto)
{
	return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
		  h_proto == bpf_htons(ETH_P_8021AD));
}

/*
 *	struct vlan_hdr - vlan header
 *	@h_vlan_TCI: priority and VLAN ID
 *	@h_vlan_encapsulated_proto: packet type ID or len
 */
struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto; /* NOTICE: unsigned type */
};

/* Packet parsing helpers.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in host byte order.
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh, void *data_end,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);
	struct vlan_hdr *vlh;
	__u16 h_proto;
	int i;

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;
	vlh = nh->pos;
	h_proto = eth->h_proto;

	/* Use loop unrolling to avoid the verifier restriction on loops;
	 * support up to VLAN_MAX_DEPTH layers of VLAN encapsulation.
	 */
	#pragma unroll
	for (i = 0; i < VLAN_MAX_DEPTH; i++) {
		if (!proto_is_vlan(h_proto))
			break;

		if (vlh + 1 > data_end)
			break;

		h_proto = vlh->h_vlan_encapsulated_proto;
		vlh++;
	}

	nh->pos = vlh;
	return h_proto; /* network-byte-order */
}

/* Assignment 2: Implement and use this */
static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr)
{
    struct ipv6hdr *v6hdr = nh->pos;
    int hdrsize = sizeof(struct ipv6hdr);
    if (nh->pos + hdrsize > data_end )
        return -1;

    nh->pos += hdrsize;
    *ip6hdr = v6hdr;

    return v6hdr->nexthdr;
}

static __always_inline int parse_ip4hdr(struct hdr_cursor *nh,
					void *data_end,
					struct iphdr **ip4hdr)
{
    int hdrsize = sizeof(struct iphdr);
    if (nh->pos + hdrsize > data_end )
        return -1;

    *ip4hdr = nh->pos;
    nh->pos += hdrsize;

    return (*ip4hdr)->protocol;
}

/* Assignment 3: Implement and use this */
static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmp6hdr **icmpv6hdr)
{
    int hdrsize = sizeof(struct icmp6hdr);
    if (nh->pos + hdrsize > data_end)
        return -1;

    *icmpv6hdr = nh->pos;
    nh->pos +=  hdrsize;

    return (*icmpv6hdr)->icmp6_type;
}

static __always_inline int parse_icmp4hdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmphdr **icmpv4hdr)
{
    int hdrsize = sizeof(struct icmphdr);
    if (nh->pos + hdrsize > data_end)
        return -1;

    *icmpv4hdr = nh->pos;
    nh->pos +=  hdrsize;

    return (*icmpv4hdr)->type;
}

SEC("xdp_packet_parser")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;
	struct ipv6hdr *ip6hdr;
	struct iphdr *ip4hdr;
	struct icmp6hdr *icmpv6hdr;
	struct icmphdr *icmpv4hdr;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_DROP; /* Default action */

        /* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type, nh_proto, icmp_type;

	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type == bpf_htons(ETH_P_IPV6))
	{
	    nh_proto = parse_ip6hdr(&nh, data_end, &ip6hdr);
        if (nh_proto == IPPROTO_ICMPV6)
        {
            icmp_type = parse_icmp6hdr(&nh, data_end, &icmpv6hdr);
            if (icmp_type == ICMPV6_ECHO_REPLY || icmp_type == ICMPV6_ECHO_REQUEST)
            {
                if (bpf_ntohs(icmpv6hdr->icmp6_sequence) & 0x1)
                    action = XDP_PASS;
            }
            goto out;
        } else if (nh_proto == IPPROTO_TCP)
        {
            action = XDP_TX;
            goto out;
        }
    }
    else if (nh_type == bpf_htons(ETH_P_IP))
    {
		nh_proto = parse_ip4hdr(&nh, data_end, &ip4hdr);
        if (nh_proto == IPPROTO_ICMP)
        {
            icmp_type = parse_icmp4hdr(&nh, data_end, &icmpv4hdr);

            if (icmp_type == ICMP_ECHOREPLY || icmp_type == ICMP_ECHO)
            {
                if (bpf_ntohs(icmpv4hdr->un.echo.sequence) & 0x1)
                    action = XDP_PASS;
            }
            goto out;
        } else if (nh_proto == IPPROTO_TCP)
        {
            action = XDP_TX;
            goto out;
        }
    }
    else {
        action = XDP_ABORTED;
        goto out;
    }

out:
	return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
}

char _license[] SEC("license") = "GPL";
