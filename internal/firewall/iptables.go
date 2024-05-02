package firewall

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gutmensch/podnat-controller/internal/api"
	"github.com/gutmensch/podnat-controller/internal/common"
	"github.com/gutmensch/podnat-controller/internal/state"
	"net"
	"strings"
	"time"

	"golang.org/x/exp/slices"
	"k8s.io/klog/v2"

	"github.com/coreos/go-iptables/iptables"
)

type IpTablesProcessor struct {
	ipt                      *iptables.IPTables
	chains                   []api.IpTablesChain
	rules                    map[string][]*api.NATRule
	publicNodeIP             *net.IPAddr
	jumpChainRefreshDuration time.Duration
	jumpChainPosition        map[string]int16
	ruleStalenessDuration    time.Duration
	internalNetworks         []string
	state                    state.StateStore
}

func (p *IpTablesProcessor) Apply(event *api.PodInfo) error {
	// cases
	// 1. ip:port mapping does not exist at all and add event => simple add to slice
	// 2. ip:port mapping does exist and delete event and same pod => simple delete from slice
	// 3. ip:port mapping does exist and update event and same pod => update lastVerified for same pod
	// 4. ip:port mapping does exist and add/update event from a new pod or namespace => add to slice (latest Created date will be reconciled in function)

NATRULES:
	for _, entry := range event.Annotation.TableEntries {

		var effSourceIP *net.IPAddr
		if entry.SourceIP != nil {
			effSourceIP = common.ParseIP(*entry.SourceIP)
		} else {
			effSourceIP = p.publicNodeIP
		}

		if effSourceIP == nil {
			klog.Warningf("could not detect source IP from annotation entry or from node, skipping entry %v\n", entry)
			continue
		}

		key := fmt.Sprintf("%s:%d", effSourceIP, entry.SourcePort)

		// case 1 - new entry
		if _, ok := p.rules[key]; !ok {
			klog.Warningf("creating new NAT rule for %s => %s:%d\n", key, event.IPv4, entry.DestinationPort)
			p.rules[key] = append(p.rules[key], &api.NATRule{
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
					klog.Warningf(
						"marking pod NAT rule for deletion %s => %s:%d (%s)\n",
						key,
						event.IPv4,
						entry.DestinationPort,
						event.Name,
					)
					p.rules[key][i].LastVerified = time.Now().Add(-p.ruleStalenessDuration)
				case "update":
					klog.Infof("refreshing pod NAT rule %s => %s:%d (%s)\n", key, event.IPv4, entry.DestinationPort, event.Name)
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
		klog.Infof("appending replacement NAT rule for %s => %s:%d (%s)\n", key, event.IPv4, entry.DestinationPort, event.Name)
		p.rules[key] = append(p.rules[key], &api.NATRule{
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
		klog.Errorf("reconciling rules failed with error: %v\n", err)
		return err
	}

	return nil
}

func (p *IpTablesProcessor) ensureChain(chain api.IpTablesChain) error {
	existingChains, err := p.ipt.ListChains(chain.Table)
	if err != nil {
		klog.Errorf("listing chains of table %s failed: %v\n", chain.Table, err)
		return err
	}
	if slices.Contains(existingChains, chain.Name) {
		return nil
	}
	err = p.ipt.NewChain(chain.Table, chain.Name)
	if err != nil {
		klog.Errorf("creating chain %s in table %s failed: %v\n", chain.Name, chain.Table, err)
		return err
	}
	return nil
}

func (p *IpTablesProcessor) computeRulePosition(chain api.IpTablesChain) int {
	defaultPosition := 1

	listRules, err := p.ipt.List(chain.Table, chain.JumpFrom)
	if err != nil {
		klog.Errorf("failed listing jumpfrom chain '%s' in table '%s': %v\n", chain.JumpFrom, chain.Table, err)
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
	case chain.JumpFromPos < 0 && common.Abs(chain.JumpFromPos) <= entryCount:
		pos = entryCount + chain.JumpFromPos + 1
	// append cases
	case common.Abs(chain.JumpFromPos) > entryCount:
		pos = entryCount
	case chain.JumpFromPos == 0:
		pos = entryCount
	default:
		pos = int16(defaultPosition)
	}

	return int(pos)
}

func (p *IpTablesProcessor) ensureJumpToChain(chain api.IpTablesChain) error {
	ruleSpec := []string{
		"-m", "comment", "--comment", fmt.Sprintf("%s[jump_to_chain]", *common.ResourcePrefix), "-j", chain.Name,
	}
	ruleSpecCmp := []string{
		"-A", chain.JumpFrom, "-m", "comment", "--comment", fmt.Sprintf("\"%s[jump_to_chain]\"", *common.ResourcePrefix), "-j", chain.Name,
	}
	rulePosition := p.computeRulePosition(chain)

	// algorithm
	// 1. list all rules in ipt default chain (jumpfrom)
	// 2. if rule is not in list, insert at computed position and return
	// 3. if rule is in list, check slice index with computed position
	// 3a. if positions match return
	// 3b. if positions don't match: delete old rule, insert with position

	var err error
	rules, _ := p.ipt.List(chain.Table, chain.JumpFrom)
	ruleInList := false
	ruleInListPosition := -1
	for i, r := range rules {
		if r == strings.Join(ruleSpecCmp, " ") {
			ruleInList = true
			ruleInListPosition = i
			break
		}
	}

	// 2
	if !ruleInList {
		goto CREATE
	}

	// 3a
	if ruleInList && ruleInListPosition == rulePosition {
		return nil
	}

	// 3b
	err = p.ipt.Delete(chain.Table, chain.JumpFrom, ruleSpec...)
	if err != nil {
		klog.Errorf(
			"deleting existing rule %v in table %s at wrong position %d failed: %v\n",
			ruleSpec,
			chain.Table,
			ruleInListPosition,
			err,
		)
		return err
	}

CREATE:
	klog.Infof("adding jump rule %v in table %s: %v\n", ruleSpec, chain.Table)
	err = p.ipt.Insert(chain.Table, chain.JumpFrom, rulePosition, ruleSpec...)
	if err != nil {
		klog.Errorf("adding jump rule %v in table %s failed: %v\n", ruleSpec, chain.Table, err)
		return err
	}

	return nil
}

func (p *IpTablesProcessor) ensureDefaults(chain api.IpTablesChain) error {
	switch chain.JumpFrom {
	case "POSTROUTING":
		// avoid NAT for internal network traffic
		for i, n := range p.internalNetworks {
			ruleSpec := []string{
				"-d", n, "-m", "comment", "--comment", fmt.Sprintf("%s[no_snat_for_internal]", *common.ResourcePrefix), "-j", "RETURN",
			}
			ruleExists, err := p.ipt.Exists(chain.Table, chain.Name, ruleSpec...)
			if err != nil {
				klog.Errorf("checking for existing rule %v in table %s failed: %v\n", ruleSpec, chain.Table, err)
				return err
			}
			if ruleExists {
				continue
			}
			err = p.ipt.Insert(chain.Table, chain.Name, i+1, ruleSpec...)
			if err != nil {
				klog.Errorf("adding rule %v in table %s failed: %v\n", ruleSpec, chain.Table, err)
				return err
			}
		}
	default:
		klog.Warningf("no defaults for chain %s defined, skipping\n", chain.Name)
	}

	return nil
}

func (p *IpTablesProcessor) getRule(chain api.IpTablesChain, rule *api.NATRule) []string {
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

		for i, rule := range ruleList {
			// remove stale rule entries
			if time.Now().Sub(rule.LastVerified) >= p.ruleStalenessDuration || rule.Created.Before(_lastRuleTimestamp) {
				for _, chain := range p.chains {
					klog.Infof("[chain:%s] deleting rule %v: %v\n", chain.Name, rule, p.getRule(chain, rule))
					if *common.DryRun {
						klog.Infof("dry-run activated, not deleting rule: %v\n", rule)
						continue
					}
					err := p.ipt.DeleteIfExists(chain.Table, chain.Name, p.getRule(chain, rule)...)
					if err != nil {
						klog.Warningf("failed deleting stale rule %v: %v\n", rule, err)
					}
				}
				p.rules[k] = remove(p.rules[k], i)
			}
		}

		// empty NAT mapping - delete
		if len(p.rules[k]) == 0 {
			klog.Infof("empty NAT mapping, removing: %v\n", p.rules[k])
			delete(p.rules, k)
			continue
		}

		rule := p.rules[k][0]
		if len(p.rules[k]) > 1 {
			klog.Warningf("unexpected conflicting entries, choosing first in list: %v\n", rule)
		}
		for _, chain := range p.chains {
			if *common.DryRun {
				klog.Warningf("dry-run activated, not applying rule: %v in chain %s\n", rule, chain.Name)
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

func remove(s []*api.NATRule, index int) []*api.NATRule {
	return append(s[:index], s[index+1:]...)
}

func (p *IpTablesProcessor) fetchState() {
	bytes, err := p.state.Get()
	if err != nil {
		klog.Warningf("could not read remote state: %v\n", err)
		goto _default
	}
	err = json.Unmarshal(bytes, &p.rules)
	if err != nil {
		klog.Warningf("state format malformed: %v\n%v\n", string(bytes), err)
		goto _default
	}
	return

_default:
	p.rules = make(map[string][]*api.NATRule)
}

func (p *IpTablesProcessor) syncState() {
	// since LastVerified is updated every informer loop we
	// need to write the state basically every time
	err := p.state.Put(p.rules)
	if err != nil {
		klog.Warningf("could not sync to remote state: %v\n", err)
	}
}

func (p *IpTablesProcessor) chainJumpPos(defaultChain string) {
}

func (p *IpTablesProcessor) init() error {
	p.fetchState()
	p.publicNodeIP, _ = common.GetPublicIPAddress(4)
	p.ruleStalenessDuration, _ = time.ParseDuration("600s")
	p.jumpChainRefreshDuration, _ = time.ParseDuration("300s")
	p.internalNetworks = []string{"172.16.0.0/12", "192.168.0.0/16", "10.0.0.0/8", "127.0.0.0/8"}
	p.jumpChainPosition = map[string]int16{
		"FORWARD":     common.ParseJumpPos(*common.IptablesJump, 0),
		"PREROUTING":  common.ParseJumpPos(*common.IptablesJump, 1),
		"POSTROUTING": common.ParseJumpPos(*common.IptablesJump, 2),
	}

	// positive number = actual position in chain, if not enough rules, then use last position
	// negative number = go back from end of current list and insert there, or use last position if not enough rules
	p.chains = []api.IpTablesChain{
		{
			Name:        strings.ToUpper(fmt.Sprintf("%s_FORWARD", *common.ResourcePrefix)),
			Table:       "filter",
			JumpFrom:    "FORWARD",
			JumpFromPos: p.jumpChainPosition["FORWARD"],
		},
		{
			Name:        strings.ToUpper(fmt.Sprintf("%s_PRE", *common.ResourcePrefix)),
			Table:       "nat",
			JumpFrom:    "PREROUTING",
			JumpFromPos: p.jumpChainPosition["PREROUTING"],
		},
		{
			Name:        strings.ToUpper(fmt.Sprintf("%s_POST", *common.ResourcePrefix)),
			Table:       "nat",
			JumpFrom:    "POSTROUTING",
			JumpFromPos: p.jumpChainPosition["POSTROUTING"],
		},
	}

	for _, chain := range p.chains {
		if *common.DryRun {
			klog.Infof("dryRun mode enabled, not initializing iptables chain %s in table %s\n", chain.Name, chain.Table)
			continue
		}

		if err := p.ensureChain(chain); err != nil {
			return errors.New(
				fmt.Sprintf("initializing iptables chain %s in table %s failed with error %v\n", chain.Name, chain.Table, err),
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

		// XXX: the default chains are impacted by other ipt related software like cilium
		//      run periodically to make sure rule position is always correct
		//      otherwise we might lose source NAT mapping
		go func(chain api.IpTablesChain) {
			for {
				if err := p.ensureJumpToChain(chain); err != nil {
					klog.Warningf("setup jumping into iptables chain %s in table %s failed with error %v\n",
						chain.Name,
						chain.Table,
						err,
					)
				}
				time.Sleep(p.jumpChainRefreshDuration)
			}
		}(chain)
	}

	return nil
}

// TODO: add v6 iptables support
func NewIpTablesProcessor(remoteState state.StateStore) *IpTablesProcessor {
	ipt, err := iptables.New()
	if err != nil {
		klog.Errorf("initializing of iptables failed: %v\n", err)
	}

	proc := &IpTablesProcessor{
		ipt:   ipt,
		state: remoteState,
	}

	if err = proc.init(); err != nil {
		klog.Errorf("iptables basic setup failed: %v\n", err)
	}

	return proc
}
