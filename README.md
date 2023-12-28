## eBPF/XDP-based Load Balancer Enhancement
A control plane is added to an load balancer that was created earlier to dispatch workloads through direct server return in an eBPF/XDP framework [(see here)](https://github.com/snpsuen/XDP_DSR_Load_Balancer). Instead of hardcording the configuation, user-defined bpf maps are applied together with a ring buffer to manage the backend servers, load balancer, track the dispatch activities and others. 

The load balancer is implemented by a bpf program running in the kernel space under the control of a user space program.


The repository holds the source code of implementing an L4 load balancer by means of a eBPF program running through XDP path in the kernel.

The purpose of this repo is to decouple the frontend and backend functions of the Marketplus dapp [(see here)](https://github.com/snpsuen/Marketplus) into separate Kubernetes microservices. 

More specifcally, a backend K8s pod is dedicated to running the local Ganache blockchain to serve the smart contract at work. Meanwhile, the webapp frontend is implemented by another K8s pod to invoke the smart contract remotely on the Ganache pod. It also provides a development environment for compiling and deploying the smart contract to Ganache.

![Interaction between dapp components in Kubernetes](https://raw.githubusercontent.com/snpsuen/Marketplus/main/src/dapp_segmentation_kubernetes02.png)
