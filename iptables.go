package main

import (
	"fmt"

	"github.com/golang/glog"

	"github.com/coreos/go-iptables/iptables"
)

type IpTablesProcessor struct {
	ipt *iptables.IPTables
}

func (p *IpTablesProcessor) update(event *PodInfo) {
	glog.Infof("iptables trigger, reconciling with pod: %v\n", event)
	if !*dryRun {
		// Saving the list of chains before executing tests
		originaListChain, err := p.ipt.ListChains("filter")
		if err != nil {
			glog.Errorf("ListChains of Initial failed: %v\n", err)
		}
		fmt.Printf("ListChains: %v\n", originaListChain)
	}
}

func NewIpTablesProcessor() *IpTablesProcessor {
	newIPT, err := iptables.New()
	if err != nil {
		glog.Fatalf("Init of iptables failed: %v\n", err)
	}
	proc := &IpTablesProcessor{
		// TODO: add v6 support later
		ipt: newIPT,
	}
	return proc
}
