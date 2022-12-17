/*
  no-op template for a firewall processor
  use this as example for nftables, etc.
*/

package main

import "k8s.io/klog/v2"

type DummyProcessor struct{}

func NewDummyProcessor() *DummyProcessor {
	klog.Warningf("firewall flavor '%s' not implemented, please use a supported firewall", *firewallFlavor)
	proc := &DummyProcessor{}
	return proc
}

func (p *DummyProcessor) Apply(event *PodInfo) error {
	klog.Warningf("firewall flavor '%s' not implemented, please use a supported firewall", *firewallFlavor)
	return nil
}
