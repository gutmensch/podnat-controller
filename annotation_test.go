package main

import (
	"reflect"
	"testing"
)

func TestAnnotationJSON(t *testing.T) {
	goodInput := `{"entries":[
	{"srcPort":25,"dstPort":25},
	{"ifaceAuto":false,"srcIP":"192.168.1.10","srcPort":143,"dstPort":143},
	{"srcPort":8888,"dstPort":18888,"proto":"udp"}
	]}`
	expectedOutput := &PodNatAnnotation{
		TableEntries: []NATDefinition{
			{InterfaceAutoDetect: true, SourceIP: nil, SourcePort: 25, DestinationPort: 25, Protocol: "tcp"},
			{InterfaceAutoDetect: false, SourceIP: ptr("192.168.1.10"), SourcePort: 143, DestinationPort: 143, Protocol: "tcp"},
			{InterfaceAutoDetect: true, SourceIP: nil, SourcePort: 8888, DestinationPort: 18888, Protocol: "udp"},
		},
	}

	out, err := parseAnnotation(goodInput)
	if err != nil {
		t.Fatal("Failure message", err)
	}

	if !reflect.DeepEqual(expectedOutput, out) {
		t.Fatal("Actual output does not match expected output")
	}
}
