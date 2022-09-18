package main

import (
	"fmt"
	"net"
	"strings"

	"github.com/golang/glog"
	"golang.org/x/exp/slices"

	"github.com/coreos/go-iptables/iptables"
)

// TODO
// 1. -t filter -A FORWARD -d 10.244.5.22/32 -p tcp -m conntrack --ctstate NEW -m tcp -m multiport --dports 80,443 -m comment --comment "ansible[v4_filter]" -j ACCEPT
// 2. -t nat -A PREROUTING -d 65.108.70.29/32 -p tcp -m tcp --dport 80 -m comment --comment "ansible[v4_nat]" -j DNAT --to-destination 10.244.5.22:80
//    -t nat -A PREROUTING -d 65.108.70.29/32 -p tcp -m tcp --dport 443 -m comment --comment "ansible[v4_nat]" -j DNAT --to-destination 10.244.5.22:443
// 3. -t nat -A CILIUM_POST_nat -s 10.244.4.0/22 ! -d 10.244.4.0/22 ! -o cilium_+ -m comment --comment "cilium masquerade non-cluster" -j MASQUERADE

type IpTablesRule struct {
	Protocol        string
	SourceIP        net.Addr
	SourcePort      uint16
	DestinationIP   net.Addr
	DestinationPort uint16
	Comment         string
}

type IpTablesChain struct {
	Name         string
	Table        string
	JumpChain    string
	JumpPosition uint8
}

type IpTablesProcessor struct {
	ipt    *iptables.IPTables
	chains []IpTablesChain
	rules  []IpTablesRule
}

const RESOURCE_PREFIX = "podnat"

func (p *IpTablesProcessor) apply(event *PodInfo) error {
	glog.Infof("iptables trigger, reconciling with pod: %v\n", event)
	if *dryRun {
		glog.Infof("dryRun mode enabled, not updating iptables chains for pod event\n")
		return nil
	}
	return nil
}

func (p *IpTablesProcessor) reconcile() error {
	glog.Infoln("tbd")
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
	ip, _ := getPublicIPAddress(4)
	glog.Infoln(ip)

	// XXX: static definition of chains and positions
	p.chains = []IpTablesChain{
		{
			Name:         strings.ToUpper(fmt.Sprintf("%s_FORWARD", RESOURCE_PREFIX)),
			Table:        "filter",
			JumpChain:    "FORWARD",
			JumpPosition: 1,
		},
		{
			Name:         strings.ToUpper(fmt.Sprintf("%s_PRE", RESOURCE_PREFIX)),
			Table:        "nat",
			JumpChain:    "PREROUTING",
			JumpPosition: 1,
		},
		{
			Name:         strings.ToUpper(fmt.Sprintf("%s_POST", RESOURCE_PREFIX)),
			Table:        "nat",
			JumpChain:    "POSTROUTING",
			JumpPosition: 1,
		},
	}

	for _, chain := range p.chains {
		if *dryRun {
			glog.Infof("dryRun mode enabled, not initializing iptables chain %s in table %s\n", chain.Name, chain.Table)
			continue
		}
		if err := p.ensureChain(chain.Table, chain.Name); err != nil {
			glog.Errorf("initializing iptables chain %s in table %s failed with error %v\n", chain.Name, chain.Table, err)
		}
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
