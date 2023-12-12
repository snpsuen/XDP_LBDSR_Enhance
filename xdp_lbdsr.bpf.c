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
	__type(value, struct serveraddr);
	__uint(max_entries, 1);
} lb_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, uint32_t);
	__uint(max_entries, 1024);
} serverindex_map SEC(".maps");

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
		
	if (iph->daddr == lbent->ipaddr) {
		struct five_tuple forward_key = {};
		forward_key.protocol = iph->protocol;
		forward_key.ip_source = iph->saddr;
		forward_key.ip_destination = iph->daddr;
		forward_key.port_source = bpf_ntohs(tcph->source);
		forward_key.port_destination = bpf_ntohs(tcph->dest);
		
		uint32_t* forward_backend = bpf_map_lookup_elem(&forward_flow, &forward_key);
		if (forward_backend == NULL) {
			uint32_t indexkey = 0;
			uint32_t* backendtotal = bpf_map_lookup_elem(&serverindex_map, &indexkey);
			if (backendtotal == NULL || *backendtotal < 1) {
				bpf_printk("Invalid number of backend servers\n");
				return XDP_PASS;
			}
			
			uint32_t selectedindex = (bpf_get_prandom_u32() % *backendtotal) + 1;
			uint32_t* selectedkey = bpf_map_lookup_elem(&serverindex_map, &selectedindex);
			if (selectedkey == NULL) {
				bpf_printk("Cannot look up the server key for the selected index %d\n", selectedindex);
				return XDP_PASS;
			}
			
			struct serveraddr* newbackend = bpf_map_lookup_elem(&server_map, selectedkey);
			if (newbackend == NULL) {
				bpf_printk("Cannot look up the new backend for the selected server key  %d\n", *selectedkey);
				return XDP_PASS;
			}
			
			forward_backend = selectedkey;
			bpf_map_update_elem(&forward_flow, &forward_key, forward_backend, BPF_ANY);
		}
		
		struct serveraddr* backend = bpf_map_lookup_elem(&server_map, forward_backend);
		if (backend == NULL) {
			bpf_printk("Cannot look up the server for the forward backend key  %d\n", *forward_backend);
			return XDP_PASS;
		}
		
		for (int i = 0; i < 6; i++) {      
			eth->h_dest[i] = backend->macaddr[i];
			eth->h_source[i] = lbent->macaddr[i];
		}
		
		struct dispatchmsg_t dmsg;
		dmsg.timestamp = bpf_ktime_get_ns();
		dmsg.saddr = iph->saddr;
		dmsg.backendkey = *forward_backend;
		bpf_ringbuf_output(&dispatch_ring, &dmsg, sizeof(dmsg), BPF_RB_FORCE_WAKEUP);
        
        return XDP_TX;
    }
    
    return XDP_PASS;
}
