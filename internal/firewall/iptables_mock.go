package firewall

import "github.com/coreos/go-iptables/iptables"

// used for testing
type IPTablesMock struct {
	PreroutingRules  []string
	ForwardRules     []string
	PostroutingRules []string
}

func (i IPTablesMock) Proto() iptables.Protocol { return iptables.ProtocolIPv4 }
func (i IPTablesMock) Exists(table string, chain string, rulespec ...string) (bool, error) {
	return true, nil
}
func (i IPTablesMock) Insert(table string, chain string, pos int, rulespec ...string) error {
	return nil
}
func (i IPTablesMock) Replace(table string, chain string, pos int, rulespec ...string) error {
	return nil
}
func (i IPTablesMock) InsertUnique(table string, chain string, pos int, rulespec ...string) error {
	return nil
}
func (i IPTablesMock) Append(table string, chain string, rulespec ...string) error       { return nil }
func (i IPTablesMock) AppendUnique(table string, chain string, rulespec ...string) error { return nil }
func (i IPTablesMock) Delete(table string, chain string, rulespec ...string) error       { return nil }
func (i IPTablesMock) DeleteIfExists(table string, chain string, rulespec ...string) error {
	return nil
}
func (i IPTablesMock) ListById(table string, chain string, id int) (string, error) { return "", nil }
func (i IPTablesMock) List(table string, chain string) ([]string, error)           { return []string{}, nil }
func (i IPTablesMock) ListWithCounters(table string, chain string) ([]string, error) {
	return []string{}, nil
}
func (i IPTablesMock) ListChains(table string) ([]string, error)                        { return []string{}, nil }
func (i IPTablesMock) ChainExists(table string, chain string) (bool, error)             { return true, nil }
func (i IPTablesMock) NewChain(table string, chain string) error                        { return nil }
func (i IPTablesMock) ClearChain(table string, chain string) error                      { return nil }
func (i IPTablesMock) RenameChain(table string, oldChain string, newChain string) error { return nil }
func (i IPTablesMock) DeleteChain(table string, chain string) error                     { return nil }
func (i IPTablesMock) ClearAndDeleteChain(table string, chain string) error             { return nil }
func (i IPTablesMock) ClearAll() error                                                  { return nil }
func (i IPTablesMock) DeleteAll() error                                                 { return nil }
func (i IPTablesMock) ChangePolicy(table string, chain string, target string) error     { return nil }
