# Simple stupid pod NAT controller

Instead of using sophisticated load balancing, this controller is just watching for pod annotations and creating related iptables node NAT entries to send traffic to a pod on a specific port directly. The deployment pod needs NET_ADMIN privileges.

## Annotation format

TCP example (default)
```
bln.space/pod-nat: 25:25,143:143,587:587
```

UDP example
```
bln.space/pod-nat: 8888:8888:udp
```
