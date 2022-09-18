package main

// simple interface to handle NAT definitions
// currently only implemented by legacy iptables (iptables.go)
// because k8s still depends on it, even without kube-proxy
// XXX: add support for nftables etc. later
type FirewallProcessor interface {
	init() error
	apply(event *PodInfo) error
	reconcile() error
}
