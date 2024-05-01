# Simple stupid pod NAT controller

Instead of using sophisticated load balancing, this controller is just watching for pod annotations and creating related iptables node NAT entries to send traffic to a pod on a specific port directly, and return the traffic over the same public IP. This can be useful for single pod ingress deployments or mail server pods, which need direct NAT for IP lookups, etc. The DaemonSet pods needs `NET_ADMIN` privileges and `hostNetwork: true` setting.

## Annotation format

The JSON format expects a list (holding port objects) called 'entries' in the top level object. The entries for this list use following values

| key       | value        | required | default | description                                         |
| --------- | ------------ | -------- | ------- | --------------------------------------------------- |
| ifaceAuto | true/false   | no       | true    | auto detect and use public interface resp. IP       |
| srcIP     | IPv4 address | no       |         | source IP for NAT entry to pod (for manual setting) |
| srcPort   | 1-65535      | yes      |         | source port for NAT entry                           |
| dstPort   | 1-65535      | yes      |         | destination port for NAT entry                      |
| proto     | tcp/udp      | no       | tcp     | layer 3 protocol for NAT entry                      |

### Pod annotation example for a mail server (auto detect public node IP)

```yaml
bln.space/podnat: '{"entries":[{"srcPort":25,"dstPort":25},{"srcPort":143,"dstPort":143},{"srcPort":587,"dstPort":587}]}'
```

### Pod annotation example for a mail server (manual IP setting)

```yaml
bln.space/podnat: '{"entries":[{"ifaceAuto":false,"srcIP":"192.168.2.94","srcPort":25,"dstPort":25},{"ifaceAuto":false,"srcIP":"192.168.2.94","srcPort":143,"dstPort":143},{"ifaceAuto":false,"srcIP":"192.168.2.94","srcPort":587,"dstPort":587}]}'
```

## Controller flags

The following flags can be adjusted with the `extraArgs` setting in the chart.

| flag             | type   | required | default                      | example                        | description                                 |
| ---------------- | ------ | -------- | ---------------------------- | ------------------------------ | ------------------------------------------- |
| -dryrun          | bool   | no       | false                        | -dryrun                        | just print changes to firewall              |
| -annotationkey   | string | no       | bln.space/podnat             | -annotationkey=example.com/nat | annotation for pods                         |
| -informerresync  | int    | no       | 180                          | -informerresync=600            | interval of automatic pod informer refresh  |
| -restrictedports | string | no       | 22,53,6443                   | -restrictedports=22,6443       | configure NAT excluded ports                |
| -httpport        | int    | no       | 8484                         | -httpport=8585                 | http port for pod nat controller daemon set |
| -firewallflavor  | string | no       | iptables                     | -firewallflavor=other          | firewall NAT implementation<sup>1</sup>     |
| -inclfilternet   | string | no       |                              | -inclfilternet=1.3.5.7/32      | ignore during auto detection                |
| -exclfilternet   | string | no       |                              | -exclfilternet=192.168.1.0/24  | allow address from net<sup>2</sup>          |
| -resourceprefix  | string | no       | podnat                       | -resourceprefix=iloveipt       | prefix for chains in iptables               |
| -stateflavor     | string | no       | webdav                       | -stateflavor=other             | use different state impl<sup>3</sup>        |
| -stateuri        | string | no       | http://podnat-state-store:80 | -stateuri=http://othersvc:80   | state URI endpoint                          |

<sup>1</sup>Currently only iptables v4 available

<sup>2</sup>By default RFC1918 internal networks are not considered during auto detection

<sup>3</sup>Currently only webdav state side deployment available

## Local testing

Dry-run will print firewall changes only. The controller filters for its own kubernetes node hostname, so you need to spoof this information via environment variable for local testing.

```bash
export KUBECONFIG=$HOME/.kube/config
go build
HOSTNAME=<kubernetes_node_name> ./podnat-controller -stateuri=http://localhost:8080 -excludefilternetworks=192.168.0.0/16 -logtostderr -dryrun
```

## Installation

```bash
helm upgrade \
  -n podnat-controller-system \
  --install \
  --repo https://remembrance.github.io/podnat-controller \
  --debug \
  --set-json='extraArgs=["-dryrun"]'
  podnat-controller \
  podnat-controller
```

## Limitations

- last created pod with same assignment wins

- TODO: UDP support

- TODO: iptables and interface v6 support

- TODO: replace NAT state store with etcd/configmap (currently WebDAV)

- iptables logic "use at your own risk" - it might break your ssh access, if you allow port 22 and deploy a NAT rule, you have been warned :-)
