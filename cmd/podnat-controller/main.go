package main

import (
	"flag"
	"github.com/gutmensch/podnat-controller/internal/api"
	"github.com/gutmensch/podnat-controller/internal/common"
	"github.com/gutmensch/podnat-controller/internal/controller"
	"github.com/gutmensch/podnat-controller/internal/firewall"
	"github.com/gutmensch/podnat-controller/internal/http"
	"github.com/gutmensch/podnat-controller/internal/state"
	"k8s.io/klog/v2"
)

var (
	fwProc  firewall.Processor
	fwState state.StateStore
)

func init() {
	klog.InitFlags(nil)
	flag.StringVar(&common.AnnotationKey, "annotationKey", "bln.space/podnat", "pod annotation key for iptables NAT trigger")
	flag.IntVar(&common.HTTPPort, "httpPort", 8484, "http service port number")
	flag.IntVar(&common.InformerResync, "informerResync", 180, "kubernetes informer resync interval")
	flag.BoolVar(&common.DryRun, "dryRun", false, "execute iptables commands or print only")
	flag.StringVar(&common.RestrictedPorts, "restrictedPorts", "22,53,6443", "restricted ports refused for NAT rule")
	flag.StringVar(&common.FirewallFlavor, "firewallFlavor", "iptables", "firewall implementation to use for NAT setup")
	flag.StringVar(&common.IptablesJump, "iptablesJump", "-2,-2,-2", "rule pos for chain jump to podnat (FORWARD,PREROUTING,POSTROUTING)")
	flag.StringVar(&common.IncludeFilterNetworks, "inclFilterNet", "", "disable networks during auto detection")
	flag.StringVar(&common.ExcludeFilterNetworks, "exclFilterNet", "", "enable networks during auto detection (e.g. RFC1918)")
	flag.StringVar(&common.ResourcePrefix, "resourcePrefix", "podnat", "resource prefix used for firewall chains and comments")
	flag.StringVar(&common.NodeID, "nodeID", common.ShortHostName(common.GetEnv("HOSTNAME", "node")), "k8s node identifier")
	flag.StringVar(&common.StateFlavor, "stateFlavor", "configmap", "state implementation to save iptables rules")
	flag.Parse()
}

func main() {
	events := make(chan *api.PodInfo)

	podInformer := controller.NewPodInformer([]string{"add", "update", "delete"}, events)
	go podInformer.Run()

	httpServer := http.NewHTTPServer()
	go httpServer.Run()

	switch common.StateFlavor {
	case "webdav":
		fwState = state.NewWebDavState()
	default:
		fwState = state.NewConfigMapState()
	}

	switch common.FirewallFlavor {
	case "iptables":
		// XXX: with iptables we need a state to survive pod/node restarts
		fwProc = firewall.NewIpTablesProcessor(fwState)
	default:
		fwProc = firewall.NewDummyProcessor()
	}

	for {
		podNatEvent := <-events
		_ = fwProc.Apply(podNatEvent)
	}
}
