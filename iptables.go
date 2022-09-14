package main

import (
	"github.com/golang/glog"
	"golang.org/x/exp/slices"

	"github.com/coreos/go-iptables/iptables"
)

type IpTablesProcessor struct {
	ipt *iptables.IPTables
}

const PODNAT_CHAIN = "PODNAT"

func (p *IpTablesProcessor) update(event *PodInfo) error {
	glog.Infof("iptables trigger, reconciling with pod: %v\n", event)
	if *dryRun {
		glog.Infof("dryRun mode enabled, not updating iptables chains for pod event\n")
		return nil
	}
	return nil
}

func (p *IpTablesProcessor) ensureChain(table, name string) error {
	existingChains, err := p.ipt.ListChains(table)
	if err != nil {
		glog.Errorf("listing chains of tables %s failed: %v\n", table, err)
		return err
	}
	if !slices.Contains(existingChains, name) {
		err = p.ipt.NewChain(table, name)
		if err != nil {
			glog.Errorf("creating chain %s in table %s failed: %v\n", name, table, err)
			return err
		}
	}
	return nil
}

func (p *IpTablesProcessor) init() error {
	ip, _ := GetPublicIPAddress(4)
	glog.Infoln(ip)

	if *dryRun {
		glog.Infof("dryRun mode enabled, not initializing iptables chains and rules\n")
		return nil
	}

	// create custom chains in tables
	if err := p.ensureChain("filter", PODNAT_CHAIN); err != nil {
		glog.Errorf("initializing iptables chain %s in table filter failed with error %v\n", PODNAT_CHAIN, err)
	}
	if err := p.ensureChain("nat", PODNAT_CHAIN); err != nil {
		glog.Errorf("initializing iptables chain %s in table nat failed with error %v\n", PODNAT_CHAIN, err)
	}

	// make sure we jump to chain as late as possible to allow for other local entries
	return nil
}

// TODO: add v6 iptables support
func NewIpTablesProcessor() *IpTablesProcessor {
	ipt, err := iptables.New()
	if err != nil {
		glog.Fatalf("init of iptables failed: %v\n", err)
	}

	proc := &IpTablesProcessor{
		ipt: ipt,
	}

	if err = proc.init(); err != nil {
		glog.Fatalf("init of iptables chains failed: %v\n", err)
	}

	return proc
}
