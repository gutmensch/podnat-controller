# Simple stupid pod NAT controller

Instead of using sophisticated load balancing, this controller is just watching for pod annotations and creating related iptables node NAT entries to send traffic to a pod on a specific port directly. This can be useful for single pod ingress deployments or mail server pods, which need direct NAT for IP lookups, etc. The DaemonSet pods needs `NET_ADMIN` privileges and `hostNetwork: true` setting. It runs as daemonset, because NAT rule and pod placement are currently only supported for the *same node*.

## Annotation format

The JSON format expects a list (holding port objects) called 'ports' in the top level object. The entries for this list use following values

```
pubif: true|false (default: true) - use public interface of node for NAT prerouting/forwarding, if false node local interface is tried
src: [int] (required) - source port for NAT entry
dst: [int] (required) - destination port for NAT entry
proto: tcp|udp (default: tcp) - layer 3 protocol for NAT entry
```

TCP example for a mail server
```
bln.space/podnat: '{"ports":[{"src":25,"dst":"25"},{"src":143,"dst":"143"},{"src":587,"dst":"587"}]}'
```

UDP example for some rogue service
```
bln.space/podnat: '{"ports":[{"src":8888,"dst":8888,"proto":"udp"}]}
```

## Local testing

Dry-run will print iptables changes only.

```
export KUBECONFIG=$HOME/.kube/config
go build
HOSTNAME=<kubernetes_node_name> ./podnat-controller -logtostderr -dryrun=true
```

## Limitations

The software is stupid and cannot fix double assigned NAT ports! Use annotations carefully and use at your own risk. ;-)
