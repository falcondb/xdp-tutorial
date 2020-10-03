/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp_abort")
int  xdp_drop_func(struct xdp_md *ctx)
{
	return XDP_ABORTED;
}

SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *xx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
