// SPDX-License-Identifier: (LGPL-2.1-or-later OR BSD-2-Clause)

#include "vmlinux0.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xdp_lbdsr.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, struct serveraddr);
    __uint(max_entries, 1024);
} server_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, uint32_t);
	__uint(max_entries, 1);
} totalserver_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, struct serveraddr);
	__uint(max_entries, 1);
} lb_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 4096);
} dispatch_ring SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct five_tuple);
	__type(value, uint32_t);
	__uint(max_entries, 100000);
} forward_flow SEC(".maps");


SEC("xdp")
int dispatchworkload(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* bpf_printk("got something"); */
	
	struct ethhdr *eth = (struct ethhdr*)data;
	if ((void*)eth + sizeof(struct ethhdr) > data_end)
		return XDP_ABORTED;
	if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
		return XDP_PASS;
	
	struct iphdr* iph = (struct iphdr*)((void*)eth + sizeof(struct ethhdr));
	if ((void*)iph + sizeof(struct iphdr) > data_end)
		return XDP_ABORTED;	
	if (iph->protocol != IPPROTO_TCP)
		return XDP_PASS;
	
	struct tcphdr* tcph = (struct tcphdr*)((void*)iph + sizeof(struct iphdr));
	if ((void*)tcph + sizeof(struct tcphdr) > data_end)
		return XDP_ABORTED;
	
	uint32_t addrkey = 0;
	struct serveraddr* lbent = bpf_map_lookup_elem(&lb_map, &addrkey);
	
	if (lbent == NULL) {
		bpf_printk("The load balancer map is empty\n");
		return XDP_PASS;
	}

	/* bpf_printk("Got TCP packet travelling from port %d to %d", bpf_ntohs(tcph->source), bpf_ntohs(tcph->dest));
	bpf_printk("Got TCP packet travelling from IP %x to %x", iph->saddr, iph->daddr); */
		
	if (iph->daddr == lbent->ipaddr) {
		/* bpf_printk("Packet sent from the client %x", iph->saddr);
		bpf_printk("Packet with tcp source port %d", bpf_ntohs(tcph->source));
		bpf_printk("Packet with tcp destination port %d", bpf_ntohs(tcph->dest)); */
	
		struct serveraddr* backend;
		struct five_tuple forward_key = {};
		forward_key.protocol = iph->protocol;
		forward_key.ip_source = iph->saddr;
		forward_key.ip_destination = iph->daddr;
		forward_key.port_source = bpf_ntohs(tcph->source);
		forward_key.port_destination = bpf_ntohs(tcph->dest);
		
		uint32_t* forward_backend = bpf_map_lookup_elem(&forward_flow, &forward_key);
		if (forward_backend == NULL) {
			uint32_t totalkey = 0;
			uint32_t* totalptr = bpf_map_lookup_elem(&totalserver_map, &totalkey);

			if (totalptr == NULL) {
				bpf_printk("Cannot look up the total number of backend servers\n");
				return XDP_PASS;
			}
			
			if (*totalptr == 0) {
				bpf_printk("Server map is empty");
				return XDP_PASS;
			}
			
			uint32_t selectedkey = bpf_get_prandom_u32() % *totalptr;
			backend = bpf_map_lookup_elem(&server_map, &selectedkey);
			if (backend == NULL) {
				bpf_printk("Cannot look up the new backend for the selected server key  %d\n", selectedkey);
				return XDP_PASS;
			}

			forward_backend = &selectedkey;
			bpf_map_update_elem(&forward_flow, &forward_key, forward_backend, BPF_ANY);
			bpf_printk("Added a new entry to the forward flow table for the selected backend server key %d\n", selectedkey);
		}
		else {
			backend = bpf_map_lookup_elem(&server_map, forward_backend);
			if (backend == NULL) {
				bpf_printk("Cannot look up the server for the forward backend key %d\n", *forward_backend);
				return XDP_PASS;
			}
			 bpf_printk("Located the backend server key from an existing entry in the forward flow table\n", *forward_backend);
		}

		struct dispatchmsg_t dmsg;
		dmsg.timestamp = bpf_ktime_get_ns();
		dmsg.saddr = iph->saddr;
		dmsg.backendkey = *forward_backend;
		bpf_ringbuf_output(&dispatch_ring, &dmsg, sizeof(dmsg), BPF_RB_FORCE_WAKEUP);

		bpf_printk("Packet to be forwrded to the backend server key %d\n", *forward_backend);
		for (int i = 0; i < 6; i++) {      
			eth->h_dest[i] = backend->macaddr[i];
			eth->h_source[i] = lbent->macaddr[i];
		}
		
		bpf_printk("Before XDP_TX, iph->saddr = %x, iph->daddr = %x\n", iph->saddr, iph->daddr);
		bpf_printk("Before XDP_TX, eth->h_source = %x:%x:%x:", eth->h_source[0], eth->h_source[1], eth->h_source[2]);
		bpf_printk("%x:%x:%x\n", eth->h_source[3], eth->h_source[4], eth->h_source[5]);
		bpf_printk("Before XDP_TX, eth->h_dest = %x:%x:%x:", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2]);
		bpf_printk("%x:%x:%x\n", eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
		bpf_printk("Returning XDP_TX ...\n");

		return XDP_TX;
	
		/* eth->h_dest[5] = backend->macaddr[5];
		eth->h_source[5] = lbent->macaddr[5];

		bpf_printk("Before XDP_TX, iph->saddr = %x, iph->daddr = %x", iph->saddr, iph->daddr);
		bpf_printk("Before XDP_TX, eth->h_source[5] = %x, eth->h_dest[5] = %x", eth->h_source[5], eth->h_dest[5]);
		bpf_printk("Returning XDP_TX ...");
		return XDP_TX; */
    }
    
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
