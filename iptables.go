package main

import (
	"errors"
	"fmt"
	"net"
	"strconv"
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
	Name        string
	Table       string
	JumpFrom    string
	JumpFromPos int16
}

type IpTablesProcessor struct {
	ipt    *iptables.IPTables
	chains []IpTablesChain
	rules  []IpTablesRule
}

func (p *IpTablesProcessor) Apply(event *PodInfo) error {
	// store or detect source IP for NAT
	// ip, _ := getPublicIPAddress(4)
	// glog.Infof(ip.String())
	glog.Infof("iptables trigger, applying for podinfo: %v and annotation %v\n", event, *event.Annotation)
	if *dryRun {
		glog.Infof("dryRun mode enabled, not updating iptables chains for pod event\n")
		return nil
	}

	return nil
}

func (p *IpTablesProcessor) ensureChain(chain IpTablesChain) error {
	existingChains, err := p.ipt.ListChains(chain.Table)
	if err != nil {
		glog.Errorf("listing chains of table %s failed: %v\n", chain.Table, err)
		return err
	}
	if slices.Contains(existingChains, chain.Name) {
		return nil
	}
	err = p.ipt.NewChain(chain.Table, chain.Name)
	if err != nil {
		glog.Errorf("creating chain %s in table %s failed: %v\n", chain.Name, chain.Table, err)
		return err
	}
	return nil
}

func (p *IpTablesProcessor) ensureJumpToChain(chain IpTablesChain) error {
	listRules, err := p.ipt.List(chain.Table, chain.JumpFrom)
	glog.Infof("listRules: %v\n", listRules)
	if err != nil {
		return errors.New(
			fmt.Sprintf("failed listing jumpfrom chain '%s' in table '%s': %v\n", chain.JumpFrom, chain.Table, err),
		)
	}

	// policy is first entry in rules
	entries := int16(len(listRules)) - 1
	glog.Infof("jumpfrompos: %d entries: %d\n", chain.JumpFromPos, entries)
	var pos int16
	switch {
	case chain.JumpFromPos > 0 && chain.JumpFromPos <= entries:
		pos = chain.JumpFromPos
	case chain.JumpFromPos < 0 && abs(chain.JumpFromPos) <= entries:
		pos = entries + chain.JumpFromPos
	case abs(chain.JumpFromPos) > entries:
		pos = entries + 1
	}

	addRuleSpec := []string{
		"-I",
		chain.JumpFrom,
		strconv.Itoa(int(pos)),
		"-m",
		"comment",
		"--comment",
		fmt.Sprintf("%s[jump_to_chain]", *resourcePrefix),
		"-j",
		chain.Name,
	}
	existingRuleSpec := []string{
		"-m",
		"comment",
		"--comment",
		fmt.Sprintf("%s[jump_to_chain]", *resourcePrefix),
		"-j",
		chain.Name,
	}

	ruleExists, err := p.ipt.Exists(chain.Table, chain.JumpFrom, existingRuleSpec...)
	if err != nil {
		glog.Errorf("checking for existing rule %v in table %s failed: %v\n", existingRuleSpec, chain.Table, err)
		return err
	}
	glog.Infoln(ruleExists)

	glog.Infof("adding rulespec %v\n", addRuleSpec)
	return nil
}

func (p *IpTablesProcessor) init() error {
	// chain definitions include namings and jump positions from standard chains
	// logic:
	//   positive number = actual position in chain, if not enough rules, then use last position
	//   negative number = go back from end of current list and insert there, or use last position if not enough rules
	p.chains = []IpTablesChain{
		{
			Name:        strings.ToUpper(fmt.Sprintf("%s_FORWARD", *resourcePrefix)),
			Table:       "filter",
			JumpFrom:    "FORWARD",
			JumpFromPos: -2,
		},
		{
			Name:        strings.ToUpper(fmt.Sprintf("%s_PRE", *resourcePrefix)),
			Table:       "nat",
			JumpFrom:    "PREROUTING",
			JumpFromPos: -2,
		},
		{
			Name:        strings.ToUpper(fmt.Sprintf("%s_POST", *resourcePrefix)),
			Table:       "nat",
			JumpFrom:    "POSTROUTING",
			JumpFromPos: -2,
		},
	}

	for _, chain := range p.chains {
		if *dryRun {
			glog.Infof("dryRun mode enabled, not initializing iptables chain %s in table %s\n", chain.Name, chain.Table)
			continue
		}

		// 1. create new chains for us only to segregate
		if err := p.ensureChain(chain); err != nil {
			return errors.New(
				fmt.Sprintf("initializing iptables chain %s in table %s failed with error %v\n", chain.Name, chain.Table, err),
			)
		}

		// 2. jump from default chains to our chains
		if err := p.ensureJumpToChain(chain); err != nil {
			return errors.New(
				fmt.Sprintf(
					"setup jumping into iptables chain %s in table %s failed with error %v\n",
					chain.Name,
					chain.Table,
					err,
				),
			)
		}
	}
	return nil
}

// TODO: add v6 iptables support
func NewIpTablesProcessor() *IpTablesProcessor {
	ipt, err := iptables.New()
	if err != nil {
		glog.Errorf("initializing of iptables failed: %v\n", err)
	}

	proc := &IpTablesProcessor{
		ipt: ipt,
	}

	if err = proc.init(); err != nil {
		glog.Errorf("iptables basic setup failed: %v\n", err)
	}

	return proc
}
