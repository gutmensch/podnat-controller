package api

import (
	"net"
	"time"
)

// TODO IPv6 support
type PodInfo struct {
	Event      string
	Name       string
	Namespace  string
	Node       string
	Annotation *PodNATAnnotation
	IPv4       *net.IPAddr
}

type PodNATAnnotation struct {
	TableEntries []NATDefinition `json:"entries"`
}

type NATDefinition struct {
	InterfaceAutoDetect bool    `json:"ifaceAuto"`
	SourceIP            *string `json:"srcIP"`
	SourcePort          uint16  `json:"srcPort"`
	DestinationPort     uint16  `json:"dstPort"`
	Protocol            string  `json:"proto"`
}

type NATRule struct {
	Protocol        string      `json:"Protocol"`
	SourceIP        *net.IPAddr `json:"SourceIP"`
	SourcePort      uint16      `json:"SourcePort"`
	DestinationIP   *net.IPAddr `json:"DestinationIP"`
	DestinationPort uint16      `json:"DestinationPort"`
	LastVerified    time.Time   `json:"LastVerified"`
	Created         time.Time   `json:"Created"`
	Comment         string      `json:"Comment"`
}

type IpTablesChain struct {
	Name         string
	Table        string
	ParentChain  string
	RulePosition int16
}
