/*
  no-op template for a firewall processor
  use this as example for nftables, etc.
*/

package main

import "github.com/golang/glog"

type DummyProcessor struct{}

func NewDummyProcessor() *DummyProcessor {
	glog.Warningf("firewall flavor '%s' not implemented, please use a supported firewall", *firewallFlavor)
	proc := &DummyProcessor{}
	return proc
}

func (p *DummyProcessor) Apply(event *PodInfo) error {
	glog.Warningf("firewall flavor '%s' not implemented, please use a supported firewall", *firewallFlavor)
	return nil
}
