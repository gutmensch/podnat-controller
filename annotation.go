package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/exp/slices"
)

type PodNatAnnotation struct {
	Ports []PortDefinition `json:"ports"`
}

type PortDefinition struct {
	PublicInterface bool   `json:"pubif"`
	SourcePort      uint16 `json:"src"`
	DestinationPort uint16 `json:"dst"`
	Protocol        string `json:"proto"`
}

// inject default values with custom unmarshaler
func (c *PortDefinition) UnmarshalJSON(data []byte) error {
	pd := &struct {
		PublicInterface bool   `json:"pubif"`
		SourcePort      uint16 `json:"src"`
		DestinationPort uint16 `json:"dst"`
		Protocol        string `json:"proto"`
	}{
		PublicInterface: true,
		Protocol:        "tcp",
	}
	if err := json.Unmarshal(data, pd); err != nil {
		return err
	}
	c.PublicInterface = pd.PublicInterface
	c.SourcePort = pd.SourcePort
	c.DestinationPort = pd.DestinationPort
	c.Protocol = pd.Protocol

	return nil
}

func parseAnnotation(data string) (*PodNatAnnotation, error) {
	pa := &PodNatAnnotation{}

	err := json.Unmarshal([]byte(data), pa)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("error unmarshaling data into annotation json format: %v", data))
	}
	// sanity checks for data
	for _, def := range pa.Ports {
		if def.SourcePort == 0 || def.DestinationPort == 0 {
			return nil, errors.New("port 0 is reserved and cannot be used")
		}

		if def.Protocol != "tcp" && def.Protocol != "udp" {
			return nil, errors.New("supported protocols for NAT entries are 'tcp' and 'udp'")
		}

		if !*restrictedEnable && (slices.Contains(restrictedPorts, def.SourcePort) || slices.Contains(restrictedPorts, def.DestinationPort)) {
			return nil, errors.New(fmt.Sprintf("restricted ports %s are not allowed unless specified with cmd flag -restrictedEnable", restrictedPorts))
		}
	}

	return pa, nil
}
