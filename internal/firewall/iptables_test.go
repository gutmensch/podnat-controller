package firewall

import (
	"github.com/gutmensch/podnat-controller/internal/api"
	"testing"
)

func (i IPTablesMock) Apply(e *api.PodInfo) error {
	return nil
}

func TestComputeRulePosition_0_Entries(t *testing.T) {

	proc := NewIpTablesProcessor(nil, true)
	mock := (proc.ipt).(IPTablesMock)
	mock.PreroutingRules = []string{
		"-P PREROUTING ACCEPT",
	}

	for rulePosition, expected := range map[int16]int{
		-2: 1,
		-1: 1,
		0:  1,
		1:  1,
		2:  1,
	} {
		chain := IPTablesChain{
			Name:         "PODNAT_PRE",
			Table:        "nat",
			ParentChain:  "PREROUTING",
			RulePosition: rulePosition,
		}
		pos := proc.computeRulePosition(chain, mock.PreroutingRules)
		if pos != expected {
			t.Fatalf(`requested rulePos = %d, computed rulePos = %d, want = %d`, rulePosition, pos, expected)
		}
	}
}

func TestComputeRulePosition_1_Entries(t *testing.T) {

	proc := NewIpTablesProcessor(nil, true)
	mock := (proc.ipt).(IPTablesMock)
	mock.PreroutingRules = []string{
		"-P PREROUTING ACCEPT",
		"-A PREROUTING -m comment --comment \"cilium-feeder: CILIUM_PRE_nat\" -j CILIUM_PRE_nat",
	}

	for rulePosition, expected := range map[int16]int{
		-2: 1,
		-1: 1,
		0:  1,
		1:  1,
		2:  1,
	} {
		chain := IPTablesChain{
			Name:         "PODNAT_PRE",
			Table:        "nat",
			ParentChain:  "PREROUTING",
			RulePosition: rulePosition,
		}
		pos := proc.computeRulePosition(chain, mock.PreroutingRules)
		if pos != expected {
			t.Fatalf(`computeRulePosition = %d, want %d`, pos, expected)
		}
	}
}

func TestComputeRulePosition_2_Entries(t *testing.T) {

	proc := NewIpTablesProcessor(nil, true)
	mock := (proc.ipt).(IPTablesMock)
	mock.PreroutingRules = []string{
		"-P PREROUTING ACCEPT",
		"-A PREROUTING -m comment --comment \"cilium-feeder: CILIUM_PRE_nat\" -j CILIUM_PRE_nat",
		"-A PREROUTING -m comment --comment \"cilium-feeder: CILIUM_PRE_nat\" -j CILIUM_PRE_nat",
	}

	for rulePosition, expected := range map[int16]int{
		-2: 1,
		-1: 2,
		0:  1,
		1:  1,
		2:  2,
	} {
		chain := IPTablesChain{
			Name:         "PODNAT_PRE",
			Table:        "nat",
			ParentChain:  "PREROUTING",
			RulePosition: rulePosition,
		}
		pos := proc.computeRulePosition(chain, mock.PreroutingRules)
		if pos != expected {
			t.Fatalf(`requested rulePos = %d, computed rulePos = %d, want = %d`, rulePosition, pos, expected)
		}
	}
}

func TestComputeRulePosition_3_Entries(t *testing.T) {

	proc := NewIpTablesProcessor(nil, true)
	mock := (proc.ipt).(IPTablesMock)
	mock.PreroutingRules = []string{
		"-P PREROUTING ACCEPT",
		"-A PREROUTING -m comment --comment \"cilium-feeder: CILIUM_PRE_nat\" -j CILIUM_PRE_nat",
		"-A PREROUTING -m comment --comment \"cilium-feeder: CILIUM_PRE_nat\" -j CILIUM_PRE_nat",
		"-A PREROUTING -m comment --comment \"cilium-feeder: CILIUM_PRE_nat\" -j CILIUM_PRE_nat",
	}

	for rulePosition, expected := range map[int16]int{
		-2: 2,
		-1: 3,
		0:  1,
		1:  1,
		2:  2,
	} {
		chain := IPTablesChain{
			Name:         "PODNAT_PRE",
			Table:        "nat",
			ParentChain:  "PREROUTING",
			RulePosition: rulePosition,
		}
		pos := proc.computeRulePosition(chain, mock.PreroutingRules)
		if pos != expected {
			t.Fatalf(`requested rulePos = %d, computed rulePos = %d, want = %d`, rulePosition, pos, expected)
		}
	}
}

func TestComputeRulePosition_4_Entries(t *testing.T) {

	proc := NewIpTablesProcessor(nil, true)
	mock := (proc.ipt).(IPTablesMock)
	mock.PreroutingRules = []string{
		"-P PREROUTING ACCEPT",
		"-A PREROUTING -m comment --comment \"cilium-feeder: CILIUM_PRE_nat\" -j CILIUM_PRE_nat",
		"-A PREROUTING -m comment --comment \"cilium-feeder: CILIUM_PRE_nat\" -j CILIUM_PRE_nat",
		"-A PREROUTING -m comment --comment \"cilium-feeder: CILIUM_PRE_nat\" -j CILIUM_PRE_nat",
		"-A PREROUTING -m comment --comment \"cilium-feeder: CILIUM_PRE_nat\" -j CILIUM_PRE_nat",
	}

	for rulePosition, expected := range map[int16]int{
		-2: 3,
		-1: 4,
		0:  1,
		1:  1,
		2:  2,
	} {
		chain := IPTablesChain{
			Name:         "PODNAT_PRE",
			Table:        "nat",
			ParentChain:  "PREROUTING",
			RulePosition: rulePosition,
		}
		pos := proc.computeRulePosition(chain, mock.PreroutingRules)
		if pos != expected {
			t.Fatalf(`requested rulePos = %d, computed rulePos = %d, want = %d`, rulePosition, pos, expected)
		}
	}
}
