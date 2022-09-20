package main

import "flag"

var (
	annotationKey         *string
	httpPort              *int
	informerResync        *int
	dryRun                *bool
	restrictedPorts       []uint16
	restrictedPortsEnable *bool
	firewallFlavor        *string
	resourcePrefix        *string
	fwProc                FirewallProcessor
)

func init() {
	annotationKey = flag.String("annotationkey", "bln.space/podnat", "pod annotation key for iptables NAT trigger")
	httpPort = flag.Int("httpport", 8484, "http service port number")
	informerResync = flag.Int("informerresync", 60, "kubernetes informer resync interval")
	dryRun = flag.Bool("dryrun", false, "execute iptables commands or print only")
	restrictedPorts = []uint16{22, 53, 6443}
	restrictedPortsEnable = flag.Bool("restrictedportsenable", false, "allow to also NAT restricted ports like 22 or 6443")
	firewallFlavor = flag.String("firewallflavor", "iptables", "firewall implementation to use for NAT setup")
	resourcePrefix = flag.String("resourceprefix", "podnat", "resource prefix used for firewall chains and comments")
}

func main() {
	flag.Parse()

	events := make(chan *PodInfo)

	podInformer := NewPodInformer([]string{"add", "update", "delete"}, events)
	go podInformer.Run()

	httpServer := NewHTTPServer(*httpPort)
	go httpServer.Run()

	switch *firewallFlavor {
	case "iptables":
		fwProc = NewIpTablesProcessor()
	default:
		fwProc = NewDummyProcessor()
	}

	// main loop: add/remove NAT entry for (dis)appearing pods
	for {
		podNatEvent := <-events
		_ = fwProc.Apply(podNatEvent)
	}
}
