package main

import "fmt"

type IpTablesProcessor struct {
	cmd string
}

func (p *IpTablesProcessor) update(event string) {
	fmt.Printf("trigger: updating iptables: %s", event)
}

func NewIpTablesProcessor() *IpTablesProcessor {
	proc := &IpTablesProcessor{
		cmd: "/usr/sbin/iptables",
	}
	return proc
}
