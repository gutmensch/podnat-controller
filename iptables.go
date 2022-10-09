package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/golang/glog"
	"golang.org/x/exp/slices"

	"github.com/coreos/go-iptables/iptables"
)

type IpTablesProcessor struct {
	ipt                   *iptables.IPTables
	chains                []IpTablesChain
	rules                 map[string][]*NATRule
	publicNodeIP          *net.IPAddr
	ruleStalenessDuration time.Duration
	internalNetworks      []string
	state                 StateStore
}

func (p *IpTablesProcessor) Apply(event *PodInfo) error {
	// cases
	// 1. ip:port mapping does not exist at all and add event => simple add to slice
	// 2. ip:port mapping does exist and delete event and same pod => simple delete from slice
	// 3. ip:port mapping does exist and update event and same pod => update lastVerified for same pod
	// 4. ip:port mapping does exist and add/update event from a new pod or namespace => add to slice (latest Created date will be reconciled in function)

NATRULES:
	for _, entry := range event.Annotation.TableEntries {

		var effSourceIP *net.IPAddr
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

		// case 1 - new entry
		if _, ok := p.rules[key]; !ok {
			glog.Infof("creating new NAT rule for %s => %s:%d\n", key, event.IPv4, entry.DestinationPort)
			p.rules[key] = append(p.rules[key], &NATRule{
				SourceIP:        effSourceIP,
				DestinationIP:   event.IPv4,
				SourcePort:      entry.SourcePort,
				DestinationPort: entry.DestinationPort,
				Protocol:        entry.Protocol,
				Created:         time.Now(),
				LastVerified:    time.Now(),
				Comment:         fmt.Sprintf("%s:%s", event.Namespace, event.Name),
			})
			continue
		}

		// case 2 and 3
		for i, pod := range p.rules[key] {
			if pod.DestinationIP.String() == event.IPv4.String() && pod.DestinationPort == entry.DestinationPort {
				switch event.Event {
				case "delete":
					glog.Infof(
						"marking pod NAT rule for deletion %s => %s:%d (%s)\n",
						key,
						event.IPv4,
						entry.DestinationPort,
						event.Name,
					)
					p.rules[key][i].LastVerified = time.Now().Add(-p.ruleStalenessDuration)
				case "update":
					glog.Infof("refreshing pod NAT rule %s => %s:%d (%s)\n", key, event.IPv4, entry.DestinationPort, event.Name)
					p.rules[key][i].LastVerified = time.Now()
				}
				continue NATRULES
			}
		}

		// old pod entry potentially already deleted during update operation
		// if delete we just skip to next rule
		if event.Event == "delete" {
			continue NATRULES
		}

		// case 4
		glog.Infof("appending replacement NAT rule for %s => %s:%d (%s)\n", key, event.IPv4, entry.DestinationPort, event.Name)
		p.rules[key] = append(p.rules[key], &NATRule{
			SourceIP:        effSourceIP,
			DestinationIP:   event.IPv4,
			SourcePort:      entry.SourcePort,
			DestinationPort: entry.DestinationPort,
			Protocol:        entry.Protocol,
			Created:         time.Now(),
			LastVerified:    time.Now(),
			Comment:         fmt.Sprintf("%s:%s", event.Namespace, event.Name),
		})
	}

	p.syncState()

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
	if err != nil {
		glog.Errorf("failed listing jumpfrom chain '%s' in table '%s': %v\n", chain.JumpFrom, chain.Table, err)
		return defaultPosition
	}
	// policy is first entry in rules list, real rules start with 1
	entryCount := int16(len(listRules)) - 1

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

func (p *IpTablesProcessor) getRule(chain IpTablesChain, rule *NATRule) []string {
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
			"--dport", fmt.Sprint(rule.SourcePort), "-m", "comment", "--comment", rule.Comment, "-j", "DNAT",
			"--to-destination", fmt.Sprintf("%s:%d", rule.DestinationIP, rule.DestinationPort),
		}
	case "POSTROUTING":
		return []string{
			"-s", fmt.Sprintf("%s/32", rule.DestinationIP.String()), "-p", rule.Protocol,
			"-m", "comment", "--comment", rule.Comment, "-j", "SNAT", "--to-source", rule.SourceIP.String(),
		}
	}
	return []string{}
}

func (p *IpTablesProcessor) reconcileRules() error {
	for k, ruleList := range p.rules {
		glog.Infof("ruleList: %s => %v\n", k, ruleList)

		// get last rule
		var _lastRuleTimestamp time.Time
		for _, rule := range ruleList {
			if _lastRuleTimestamp.IsZero() {
				_lastRuleTimestamp = rule.Created
			} else {
				if rule.Created.After(_lastRuleTimestamp) {
					_lastRuleTimestamp = rule.Created
				}
			}
		}
		glog.Infof("_lastRuleTimestamp: %v\n", _lastRuleTimestamp)

		for i, rule := range ruleList {
			// remove stale rule entries
			if time.Now().Sub(rule.LastVerified) >= p.ruleStalenessDuration || rule.Created.Before(_lastRuleTimestamp) {
				for _, chain := range p.chains {
					glog.Infof("[chain:%s] deleting rule %v: %v\n", chain.Name, rule, p.getRule(chain, rule))
					if *dryRun {
						glog.Infof("dry-run activated, not applying rule: %v\n", rule)
						continue
					}
					err := p.ipt.DeleteIfExists(chain.Table, chain.Name, p.getRule(chain, rule)...)
					if err != nil {
						glog.Warningf("failed deleting rule %v: %v\n", rule, err)
					}
				}
				p.rules[k] = remove(p.rules[k], i)
			}
		}

		// empty NAT mapping - delete
		if len(p.rules[k]) == 0 {
			glog.Infof("empty NAT mapping, removing: %v\n", p.rules[k])
			delete(p.rules, k)
			continue
		}

		glog.Infof("rules left: %v\n", p.rules[k])

		rule := p.rules[k][0]
		if len(p.rules[k]) > 1 {
			glog.Warningf("unexpected conflicting entries, choosing first in list: %v\n", rule)
		}
		for _, chain := range p.chains {
			if *dryRun {
				glog.Infof("dry-run activated, not applying rule: %v in chain %s\n", rule, chain.Name)
				continue
			}
			err := p.ipt.AppendUnique(chain.Table, chain.Name, p.getRule(chain, rule)...)
			if err != nil {
				return errors.New(
					fmt.Sprintf("failed appending rule for existing rule '%v' in chain '%s': %v\n", rule, chain.Name, err),
				)
			}
		}
	}

	p.syncState()

	return nil
}

func (p *IpTablesProcessor) fetchState() {
	bytes, err := p.state.Get()
	if err != nil {
		glog.Warningf("could not read remote state: %v\n", err)
		goto _default
	}
	err = json.Unmarshal(bytes, &p.rules)
	if err != nil {
		glog.Warningf("state format malformed: %v\n%v\n", string(bytes), err)
		goto _default
	}
	return

_default:
	p.rules = make(map[string][]*NATRule)
}

func (p *IpTablesProcessor) syncState() {
	// since LastVerified is updated every informer loop we
	// need to write the state basically every time
	err := p.state.Put(p.rules)
	if err != nil {
		glog.Warningf("could not sync to remote state: %v\n", err)
	}
}

func (p *IpTablesProcessor) init() error {
	p.fetchState()
	p.publicNodeIP, _ = getPublicIPAddress(4)
	p.ruleStalenessDuration, _ = time.ParseDuration("600s")
	p.internalNetworks = []string{"172.16.0.0/12", "192.168.0.0/16", "10.0.0.0/8", "127.0.0.0/8"}

	// positive number = actual position in chain, if not enough rules, then use last position
	// negative number = go back from end of current list and insert there, or use last position if not enough rules
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

	return nil
}

// TODO: add v6 iptables support
func NewIpTablesProcessor(remoteState StateStore) *IpTablesProcessor {
	ipt, err := iptables.New()
	if err != nil {
		glog.Errorf("initializing of iptables failed: %v\n", err)
	}

	proc := &IpTablesProcessor{
		ipt:   ipt,
		state: remoteState,
	}

	if err = proc.init(); err != nil {
		glog.Errorf("iptables basic setup failed: %v\n", err)
	}

	return proc
}
