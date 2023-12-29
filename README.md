## eBPF/XDP-based Load Balancer Enhancement

A control plane is added to an load balancer that was created earlier to dispatch workloads through direct server return in an eBPF/XDP framework [(see here)](https://github.com/snpsuen/XDP_DSR_Load_Balancer). Instead of hardcording the configuation, user-defined bpf maps are applied together with a ring buffer to manage the backend servers, load balancer, track the dispatch activities and others. 

The load balancer is implemented by a bpf program running in the kernel space to redirect the network traffic on the data plane under the control of a user-space program.
* xdp_lbdsr.bpf.c (Data plane in the kernel space)
* xdp_lbdsr.c (Control plane in the user space)

![Load Balancer Architecture Based on eBPF/XDP](XDP_DSR_LoadBalancer01_p2.png)

### Sample Use Case

The load balancer is tyically used for the so-called one-armed deployment, whereby it is attached via a single NIC to the same IP subnet as the client and backend servers. When the client issues a request for a service exposed from a virtual IP, the incoming traffic is routed by the load balancer to one of the backend servers in a random manner. Subsequent replies from the chosen backend server are returned directly to the client.

It is worthwhile to note that only the MAC addresses of network packets are required to change in the process. There is no need to modify any parts of the L3 headers and beyond all along.

![Delivery Of Workloads Through Direct Server Return](XDP_DSR_LoadBalancer01_p1.png)

### Set up and Experimentation

Meanwhile, you may follow the readme of the [earlier repo](https://github.com/snpsuen/XDP_DSR_Load_Balancer) to set up a testbed based on docker containers and experiment with the sample use case. A more specific set of readme instructions will be provided soon.



