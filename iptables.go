package main

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"time"

	"github.com/golang/glog"
	"golang.org/x/exp/slices"

	"github.com/coreos/go-iptables/iptables"
)

type IpTablesProcessor struct {
	ipt                   *iptables.IPTables
	chains                []IpTablesChain
	rules                 map[string]*IpTablesRule
	publicNodeIP          net.Addr
	ruleStalenessDuration time.Duration
	internalNetworks      []string
}

func (p *IpTablesProcessor) Apply(event *PodInfo) error {
	for _, entry := range event.Annotation.TableEntries {

		var effSourceIP net.Addr
		if entry.SourceIP != nil {
			effSourceIP = parseIP(*entry.SourceIP)
		} else {
			effSourceIP = p.publicNodeIP
		}

		if effSourceIP == nil {
			glog.Warningf("could not detect source IP from annotation entry or from node, skipping entry %v\n", entry)
			continue
		}

		key := fmt.Sprintf("%s:%d", effSourceIP, entry.SourcePort)

		// new entry, no old mapping found => create rule
		if _, ok := p.rules[key]; !ok {
			glog.Infof("creating new NAT rule for %s => %s:%d\n", key, event.IPv4, entry.DestinationPort)
			p.rules[key] = &IpTablesRule{
				SourceIP:        effSourceIP,
				DestinationIP:   event.IPv4,
				SourcePort:      entry.SourcePort,
				DestinationPort: entry.DestinationPort,
				Protocol:        entry.Protocol,
				OriginLabels:    event.Labels,
				LastVerified:    time.Now(),
				Comment:         fmt.Sprintf("%s:%s", event.Namespace, event.Name),
			}
			continue
		}

		currVal := p.rules[key]

		// same data, NOOP - only update LastVerified
		if currVal.DestinationIP.String() == event.IPv4.String() && currVal.DestinationPort == entry.DestinationPort {
			glog.Infof("no update needed for NAT rule %s => %s:%d\n", key, event.IPv4, entry.DestinationPort)
			p.rules[key].LastVerified = time.Now()
			continue
		}

		// conflict - pod update of existing deployment (e.g. replacement)
		if reflect.DeepEqual(currVal.OriginLabels, event.Labels) {
			glog.Infof("pod for NAT rule has been replaced, updating from %s => %s:%d to %s => %s:%d\n",
				key, currVal.DestinationIP, currVal.DestinationPort, key, event.IPv4, entry.DestinationPort)
			p.rules[key].LastVerified = time.Now()
			p.rules[key].OldDestinationIP = currVal.DestinationIP
			p.rules[key].OldDestinationPort = currVal.DestinationPort
			p.rules[key].DestinationIP = event.IPv4
			p.rules[key].DestinationPort = entry.DestinationPort
			continue
		}

		// conflict - at this point we have an existing entry that has not gone stale yet and has not been removed
		// yet, so we are refusing any overwriting. when the reconciling has deleted the stale entries, the next
		// pod update cycle will successfully create the entry, which was a conflict here before
		glog.Warningf("cowardly refusing to add new overwriting NAT rule entry for %s => %s:%d, it might succeed later.\n",
			key, event.IPv4, entry.DestinationPort)
	}

	if err := p.reconcileRules(); err != nil {
		glog.Errorf("reconciling rules failed with error: %v\n", err)
		return err
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

func (p *IpTablesProcessor) computeRulePosition(chain IpTablesChain) int {
	defaultPosition := 1

	listRules, err := p.ipt.List(chain.Table, chain.JumpFrom)
	glog.Infof("listRules: %v\n", listRules)
	if err != nil {
		glog.Errorf("failed listing jumpfrom chain '%s' in table '%s': %v\n", chain.JumpFrom, chain.Table, err)
		return defaultPosition
	}
	// policy is first entry in rules list, real rules start with 1
	entryCount := int16(len(listRules)) - 1
	glog.Infof("jumpfrompos: %d entryCount: %d\n", chain.JumpFromPos, entryCount)

	var pos int16
	switch {
	// insert from top of list down
	case chain.JumpFromPos > 0 && chain.JumpFromPos <= entryCount:
		pos = chain.JumpFromPos
	// insert from end of list up
	case chain.JumpFromPos < 0 && abs(chain.JumpFromPos) <= entryCount:
		pos = entryCount + chain.JumpFromPos + 1
	// append cases
	case abs(chain.JumpFromPos) > entryCount:
		pos = entryCount
	case chain.JumpFromPos == 0:
		pos = entryCount
	default:
		pos = int16(defaultPosition)
	}

	return int(pos)
}

func (p *IpTablesProcessor) ensureJumpToChain(chain IpTablesChain) error {
	ruleSpec := []string{
		"-m", "comment", "--comment", fmt.Sprintf("%s[jump_to_chain]", *resourcePrefix), "-j", chain.Name,
	}

	ruleExists, err := p.ipt.Exists(chain.Table, chain.JumpFrom, ruleSpec...)
	if err != nil {
		glog.Errorf("checking for existing rule %v in table %s failed: %v\n", ruleSpec, chain.Table, err)
		return err
	}

	if ruleExists {
		glog.Infof("jump to chain %s in chain %s in table %s already exists\n", chain.Name, chain.JumpFrom, chain.Table)
		return nil
	}

	err = p.ipt.Insert(chain.Table, chain.JumpFrom, p.computeRulePosition(chain), ruleSpec...)
	if err != nil {
		glog.Errorf("adding jump rule %v in table %s failed: %v\n", ruleSpec, chain.Table, err)
		return err
	}
	return nil
}

func (p *IpTablesProcessor) ensureDefaults(chain IpTablesChain) error {
	switch chain.JumpFrom {
	case "POSTROUTING":
		// avoid NAT for internal network traffic
		for i, n := range p.internalNetworks {
			ruleSpec := []string{
				"-d", n, "-m", "comment", "--comment", fmt.Sprintf("%s[no_snat_for_internal]", *resourcePrefix), "-j", "RETURN",
			}
			ruleExists, err := p.ipt.Exists(chain.Table, chain.Name, ruleSpec...)
			if err != nil {
				glog.Errorf("checking for existing rule %v in table %s failed: %v\n", ruleSpec, chain.Table, err)
				return err
			}
			if ruleExists {
				continue
			}
			err = p.ipt.Insert(chain.Table, chain.Name, i+1, ruleSpec...)
			if err != nil {
				glog.Errorf("adding rule %v in table %s failed: %v\n", ruleSpec, chain.Table, err)
				return err
			}
		}
	default:
		glog.Infof("no defaults for chain %s defined, skipping\n", chain.Name)
	}

	return nil
}

// TODO
// 1. -t filter -A FORWARD -d 10.244.5.22/32 -p tcp -m conntrack --ctstate NEW -m tcp -m multiport --dports 80,443 -m comment --comment "ansible[v4_filter]" -j ACCEPT
// 2. -t nat -A PREROUTING -d 65.108.70.29/32 -p tcp -m tcp --dport 80 -m comment --comment "ansible[v4_nat]" -j DNAT --to-destination 10.244.5.22:80
//    -t nat -A PREROUTING -d 65.108.70.29/32 -p tcp -m tcp --dport 443 -m comment --comment "ansible[v4_nat]" -j DNAT --to-destination 10.244.5.22:443
// 3. -t nat -A CILIUM_POST_nat -s 10.244.4.0/22 ! -d 10.244.4.0/22 ! -o cilium_+ -m comment --comment "cilium masquerade non-cluster" -j MASQUERADE
// -A POSTROUTING -s 10.0.0.0/24 -m comment --comment "ansible[default_nat]: ansible[default_nat]" -j MASQ_FILTER
// Match rule specifying a source port
// Below makes sure packets from Eth Devices have correct source IP Address Notice, when specifying a port, protocol needs to be specified as well
//
// iptables -t nat -A POSTROUTING -o wlan0 -s 192.168.1.2 -p udp --dport 16020 -j SNAT --to 10.1.1.7:51889
// iptables -t nat -A POSTROUTING -o wlan0 -s 192.168.1.2 -p tcp --dport 21 -j SNAT --to 10.1.1.7:21
// iptables -t nat -A POSTROUTING -o wlan0 -s 192.168.1.3 -j SNAT --to 10.1.1.9

func (p *IpTablesProcessor) getRule(chain IpTablesChain, rule *IpTablesRule) []string {
	switch chain.JumpFrom {
	case "FORWARD":
		return []string{
			"-d", fmt.Sprintf("%s/32", rule.DestinationIP.String()), "-p", rule.Protocol,
			"-m", "conntrack", "--ctstate", "NEW", "-m", rule.Protocol, "--dport", fmt.Sprint(rule.DestinationPort),
			"-m", "comment", "--comment", rule.Comment, "-j", "ACCEPT",
		}
	case "PREROUTING":
		return []string{
			"-d", fmt.Sprintf("%s/32", rule.SourceIP.String()), "-p", rule.Protocol, "-m", rule.Protocol,
			"--dport", fmt.Sprint(rule.DestinationPort), "-m", "comment", "--comment", rule.Comment, "-j", "DNAT",
			"--to-destination", fmt.Sprintf("%s:%d", rule.DestinationIP, rule.DestinationPort),
		}
	case "POSTROUTING":
		return []string{
			"-s", fmt.Sprintf("%s/32", rule.DestinationIP.String()), "-p", rule.Protocol,
			"-m", "comment", "--comment", rule.Comment, "-j", "SNAT", "--to", rule.SourceIP.String(),
		}
	}
	return []string{}
}

func (p *IpTablesProcessor) reconcileRules() error {
	for k, rule := range p.rules {
		if *dryRun {
			glog.Infof("dry-run activated, not applying rule: %v\n", rule)
			continue
		}

		// remove stale rule entries
		if time.Now().Sub(rule.LastVerified) >= p.ruleStalenessDuration {
			delete(p.rules, k)
			for _, chain := range p.chains {
				err := p.ipt.DeleteIfExists(chain.Table, chain.Name, p.getRule(chain, rule)...)
				glog.Warningf("failed deleting rule: %v\n", err)
			}
		}

		// remove rule entries where an updated pod ip target exists
		if rule.OldDestinationIP != nil && rule.OldDestinationPort != 0 {
			for _, chain := range p.chains {
				_rule := &IpTablesRule{
					DestinationIP:   rule.OldDestinationIP,
					DestinationPort: rule.OldDestinationPort,
					SourceIP:        rule.SourceIP,
					SourcePort:      rule.SourcePort,
					Protocol:        rule.Protocol,
					Comment:         rule.Comment,
				}
				err := p.ipt.DeleteIfExists(chain.Table, chain.Name, p.getRule(chain, _rule)...)
				glog.Warningf("failed deleting rule: %v\n", err)
			}
			p.rules[k].OldDestinationIP = nil
			p.rules[k].OldDestinationPort = 0
		}

		// compare iptables state vs. our rule state
		for _, chain := range p.chains {
			err := p.ipt.AppendUnique(chain.Table, chain.JumpFrom, p.getRule(chain, rule)...)
			if err != nil {
				return errors.New(
					fmt.Sprintf("failed appending rule for existing rule '%v' in chain '%s': %v\n", rule, chain.Name, err),
				)
			}
		}
	}
	return nil
}

func (p *IpTablesProcessor) init() error {
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

		if err := p.ensureChain(chain); err != nil {
			return errors.New(
				fmt.Sprintf("initializing iptables chain %s in table %s failed with error %v\n", chain.Name, chain.Table, err),
			)
		}

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

		if err := p.ensureDefaults(chain); err != nil {
			return errors.New(
				fmt.Sprintf(
					"setup default iptables chain rules %s in table %s failed with error %v\n",
					chain.Name,
					chain.Table,
					err,
				),
			)
		}

	}

	// TODO: better error handling and configuration
	p.rules = make(map[string]*IpTablesRule)
	p.publicNodeIP, _ = getPublicIPAddress(4)
	p.ruleStalenessDuration, _ = time.ParseDuration("300s")
	p.internalNetworks = []string{"172.16.0.0/12", "192.168.0.0/16", "10.0.0.0/8", "127.0.0.0/8"}

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
