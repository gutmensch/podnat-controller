# Simple stupid pod NAT controller

Instead of using sophisticated load balancing, this controller is just watching for pod annotations and creating related iptables node NAT entries to send traffic to a pod on a specific port directly. The DaemonSet pods needs `NET_ADMIN` privileges and `hostNetwork: true` setting.

## Annotation format

TCP example (default)
```
bln.space/podnat: 25:25,143:143,587:587
```

UDP example
```
bln.space/podnat: 8888:8888:udp
```

## Local testing

Dry-run will print iptables changes only.

```
export KUBECONFIG=$HOME/.kube/config
go build
HOSTNAME=<kubernetes_node_name> ./podnat-controller -logtostderr -dryrun true
```

## Limitations

The software is stupid and cannot fix double assigned NAT ports! Use annotations carefully and use at your own risk. ;-)
