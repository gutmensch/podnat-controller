package firewall

import "github.com/gutmensch/podnat-controller/internal/api"

type FirewallProcessor interface {
	Apply(event *api.PodInfo) error
}
