package main

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
	Labels     map[string]string
	IPv4       net.Addr
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
	Protocol           string            `json:"Protocol"`
	SourceIP           *net.IPAddr       `json:"SourceIP"`
	SourcePort         uint16            `json:"SourcePort"`
	DestinationIP      *net.IPAddr       `json:"DestinationIP"`
	DestinationPort    uint16            `json:"DestinationPort"`
	OldDestinationIP   *net.IPAddr       `json:"OldDestinationIP"`
	OldDestinationPort uint16            `json:"OldDestinationPort"`
	LastVerified       time.Time         `json:"LastVerified"`
	OriginLabels       map[string]string `json:"OriginLabels"`
	Comment            string            `json:"Comment"`
}

type IpTablesChain struct {
	Name        string
	Table       string
	JumpFrom    string
	JumpFromPos int16
}
