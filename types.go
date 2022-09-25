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
	Annotation *PodNatAnnotation
	Labels     map[string]string
	IPv4       net.Addr
}

type PodNatAnnotation struct {
	TableEntries []NATDefinition `json:"entries"`
}

type NATDefinition struct {
	InterfaceAutoDetect bool    `json:"ifaceAuto"`
	SourceIP            *string `json:"srcIP"`
	SourcePort          uint16  `json:"srcPort"`
	DestinationPort     uint16  `json:"dstPort"`
	Protocol            string  `json:"proto"`
}

type IpTablesRule struct {
	Protocol           string
	SourceIP           net.Addr
	SourcePort         uint16
	DestinationIP      net.Addr
	DestinationPort    uint16
	OldDestinationIP   net.Addr
	OldDestinationPort uint16
	LastVerified       time.Time
	OriginLabels       map[string]string
	Comment            string
}

type IpTablesChain struct {
	Name        string
	Table       string
	JumpFrom    string
	JumpFromPos int16
}
