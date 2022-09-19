package main

type FirewallProcessor interface {
	Apply(event *PodInfo) error
	Reconcile() error
}
