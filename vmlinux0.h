#include "vmlinux.h"

#ifndef BPF_MAP_TYPE_RINGBUF
#define BPF_MAP_TYPE_RINGBUF 27
#endif

#ifndef BPF_RB_FORCE_WAKEUP
#define BPF_RB_FORCE_WAKEUP 2
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

/* 
struct xdp_md {
  __u32 data;
  __u32 data_end;
  __u32 data_meta;
  __u32 ingress_ifindex;
  __u32 rx_queue_index;
  __u32 egress_ifindex;
};
*/
