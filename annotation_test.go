package main

import (
	"reflect"
	"testing"
)

func TestAnnotationJSON(t *testing.T) {
	goodInput := `{"ports":[{"src":25,"dst":25},{"pubif":false,"src":143,"dst":143},{"src":8888,"dst":18888,"proto":"udp"}]}`
	expectedOutput := &PodNatAnnotation{
		Ports: []PortDefinition{
			{PublicInterface: true, SourcePort: 25, DestinationPort: 25, Protocol: "tcp"},
			{PublicInterface: false, SourcePort: 143, DestinationPort: 143, Protocol: "tcp"},
			{PublicInterface: true, SourcePort: 8888, DestinationPort: 18888, Protocol: "udp"},
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
