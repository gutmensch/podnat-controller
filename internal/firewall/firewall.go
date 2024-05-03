package firewall

import "github.com/gutmensch/podnat-controller/internal/api"

type Processor interface {
	Apply(event *api.PodInfo) error
}
