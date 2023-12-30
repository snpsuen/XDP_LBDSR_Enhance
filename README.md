## eBPF/XDP-based Load Balancer Enhancement

A control plane is added to an load balancer that was created earlier to dispatch workloads through direct server return in an eBPF/XDP framework [(see here)](https://github.com/snpsuen/XDP_DSR_Load_Balancer). Instead of hardcording the configuation, user-defined bpf maps are applied together with a ring buffer to manage the backend servers, load balancer, track the dispatch activities and others. 

The load balancer is implemented by a bpf program running in the kernel space to redirect the network traffic on the data plane under the control of a user-space program.
* xdp_lbdsr.bpf.c (Data plane in the kernel space)
* xdp_lbdsr.c (Control plane in the user space)

![Load Balancer Architecture Based on eBPF/XDP](images/XDP_DSR_LoadBalancer01_p2.png)

### Use Case Example

The load balancer is tyically used for the so-called one-armed deployment, whereby it is attached via a single NIC to the same IP subnet as the client and backend servers. When the client issues a request for a service exposed from a virtual IP, the incoming traffic is routed by the load balancer to one of the backend servers in a random manner. Subsequent replies from the chosen backend server are returned directly to the client.

It is worthwhile to note that only the MAC addresses of network packets are required to change in the process. There is no need to modify any parts of the L3 headers and beyond all along.

![Delivery Of Workloads Through Direct Server Return](images/XDP_DSR_LoadBalancer01_p1.png)

### Setup and Experimentation

A testbed of docker containers is set up for experimentation with the use case example. The steps are pretty much the same as those of the [earlier repo](https://github.com/snpsuen/XDP_DSR_Load_Balancer) You may choose a Linux VM or a [Killercoda Ubuntu Playground] (https://killercoda.com/playgrounds/scenario/ubuntu) to start with as a host of the following containers.
* Load balancer: lbdsr01
* Backend Server A: backend-A
* Backend Server B: backend-B
* Curl client: curlclient01

#### 1  Build the load balancer
The load balancer is to be built on a Ubuntu container that is equipped with a full ePBF/XDP development environment.
1. Pull a pre-built eBPF/XDP ready docker to run a container as the platform of the load balancer.
```
docker run -d --privileged --name lbdsr0a -h lbdsr0a snpsuen/ebpf-xdp:v03
docker exec -it lbdsr0a bash
```
2. Download this repo and build the load balancer on both the control and data planes.
```
git clone https://github.com/snpsuen/XDP_LBDSR_Enhance
cd XDP*
make
```
3. Open a terminal to the host of the container and prepare for the on-going bpf_printk messages to be traced in real time.
```
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

#### 2  Set up backend servers
1. Run a pair of backend servers on the nginx hello docker.
```
docker run -d --privileged --name backend-A -h backend-A nginxdemos/hello:plain-text
docker run -d --privileged --name backend-B -h backend-B nginxdemos/hello:plain-text
```
2. Login to each backend containers and assign a given virtual IP (VIP) as an alias address to the loopback interface.
```
docker exec -it backend-A sh
ip addr add 192.168.25.10/24 dev lo
```
Similar steps are taken on the backend-B container.

In this case, the VIP is set arbitraily to 192.168.10.25, which is totally separate from the physical address space of the testbed, 172.17.0.0/24. It will be used by clients to access the requested service through the load balancer.

#### 3  Set up a client container
1. Run a client container based on the latest curl docker.
```
docker run -d --privileged --name curlclient -h curlclient curlimages/curl:latest sleep infinity
```
2. Add a host route to the the VIP 192.168.10.25/32 via the load balancer at 172.17.0.2.
```
docker exec -it -u root curlclient sh
ip route add 192.168.25.10/32 via 172.17.0.2
```
More realistically, say in a production environment, it is necessary to arrange for the VIP host route to be originated as a stub link for advertisement by routing protocols like OSPF and BGP throughout an autonmous system and beyond.

#### 4  Test it out

1. Enter the load balancer container and run the control plane ./xdp_lbdsr where the attached NIC and ring buffer poll interval are set to eth0 and 1000 ms respectively.
```
docker exec -it lbdsr0a bash
cd XDP_LBDSR*
./xdp_lbdsr
```
![demo_screen01](images/xdp_lbdsr_screen01.PNG)

2. Select option 2 from the main menu to specify the VIP together with the MAC of the load balancer.

![demo_screen02](images/xdp_lbdsr_screen02.PNG)

3. Select option 2 from the main menu, followed by 1 from the submenu to register the backend servers backend-A and backend-B.

![demo_screen03](images/xdp_lbdsr_screen03.PNG)

4. Enter the curl client container and access the backend nginx servers through the VIP in a loop. The http requests are observed to be dispatched randomly between backend-A and backend-B.

![demo_screen05](images/xdp_lbdsr_screen05.PNG)
