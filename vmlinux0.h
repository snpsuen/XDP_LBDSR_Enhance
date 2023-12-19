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

/* flags for BPF_MAP_UPDATE_ELEM command */
/*
enum {
        BPF_ANY         = 0, /* create new element or update existing */
        BPF_NOEXIST     = 1, /* create new element if it didn't exist */
        BPF_EXIST       = 2, /* update existing element */
        BPF_F_LOCK      = 4, /* spin_lock-ed map_lookup/map_update */
};
*/

/* flags for BPF_MAP_CREATE command */
/*
enum {
        BPF_F_NO_PREALLOC       = (1U << 0),
/* Instead of having one common LRU list in the
 * BPF_MAP_TYPE_LRU_[PERCPU_]HASH map, use a percpu LRU list
 * which can scale and perform better.
 * Note, the LRU nodes (including free nodes) cannot be moved
 * across different LRU lists.
 */
        BPF_F_NO_COMMON_LRU     = (1U << 1),
/* Specify numa node during map creation */
        BPF_F_NUMA_NODE         = (1U << 2),

/* Flags for accessing BPF object from syscall side. */
        BPF_F_RDONLY            = (1U << 3),
        BPF_F_WRONLY            = (1U << 4),

/* Flag for stack_map, store build_id+offset instead of pointer */
        BPF_F_STACK_BUILD_ID    = (1U << 5),

/* Zero-initialize hash function seed. This should only be used for testing. */
        BPF_F_ZERO_SEED         = (1U << 6),

/* Flags for accessing BPF object from program side. */
        BPF_F_RDONLY_PROG       = (1U << 7),
        BPF_F_WRONLY_PROG       = (1U << 8),

/* Clone map from listener for newly accepted socket */
        BPF_F_CLONE             = (1U << 9),

/* Enable memory-mapping BPF map */
        BPF_F_MMAPABLE          = (1U << 10),

/* Share perf_event among processes */
        BPF_F_PRESERVE_ELEMS    = (1U << 11),

/* Create a map that is suitable to be an inner map with dynamic max entries */
        BPF_F_INNER_MAP         = (1U << 12),
};
*/
