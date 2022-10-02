# Simple stupid pod NAT controller

Instead of using sophisticated load balancing, this controller is just watching for pod annotations and creating related iptables node NAT entries to send traffic to a pod on a specific port directly. This can be useful for single pod ingress deployments or mail server pods, which need direct NAT for IP lookups, etc. The DaemonSet pods needs `NET_ADMIN` privileges and `hostNetwork: true` setting. It runs as daemonset, because NAT rule and pod placement are currently only supported for the *same node*.

## Annotation format

The JSON format expects a list (holding port objects) called 'entries' in the top level object. The entries for this list use following values

|key|value|required|default|description|
|---|---|---|---|---|
|ifaceAuto|true/false|no|true| auto detect and use public interface resp. IP|
|srcIP| IPv4 address |no| |source IP for NAT entry to pod (for manual setting)|
|srcPort| 1-65535 |yes| |source port for NAT entry|
|dstPort| 1-65535 | yes | |destination port for NAT entry|
|proto| tcp/udp|no|tcp|layer 3 protocol for NAT entry|

### Pod annotation example for a mail server
```
bln.space/podnat: '{"entries":[{"srcPort":25,"dstPort":25},{"ifaceAuto":false,"srcIP":"192.168.2.94","srcPort":587,"dstPort":587}]}'
```

### Pod annotation example for some rogue UDP service
```
bln.space/podnat: '{"entries":[{"srcPort":8888,"dstPort":8888,"proto":"udp"}]}
```

## Controller flags
|flag|type|required|default|description|
|---|---|---|---|---|
|-logtostderr| bool (w/o param) |no| false | glog sending logs to stderr|
|-dryrun| bool (w/o param) |no| false | just printing changes to firewall |
|-annotationkey| string |yes| bln.space/podnat |annotation key to watch for in pods (format as above)|
|-informerresync| 0 | no | |for high traffic updates vs. k8s informer|
|-restrictedportsenable| bool (w/o param) |no|false|allow NAT entries for ports like 22 and 6443|
|-httpport| int |no|8484|http port for pod nat controller daemon set deployment|
|-firewallflavor| string |no|iptables|implementation for firewall NAT automation|

## Local testing

Dry-run will print firewall changes only. The controller filters for its own kubernetes node hostname, so you need to spoof this information via environment variable for local testing.

```
export KUBECONFIG=$HOME/.kube/config
go build
HOSTNAME=<kubernetes_node_name> ./podnat-controller -stateuri http://localhost:8080 -internalnetwork 192.168.0.0/16 -logtostderr -dryrun
```

## Limitations

The software is stupid and cannot fix double assigned NAT ports! Use annotations carefully and use at your own risk. ;-)
