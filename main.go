package main

import "flag"

var (
	annotationKey         *string
	httpPort              *int
	informerResync        *int
	dryRun                *bool
	restrictedPortsEnable *bool
	restrictedPorts       = []uint16{22, 53, 6443}
	firewallFlavor        *string
	resourcePrefix        *string
	fw                    FirewallProcessor
)

func init() {
	annotationKey = flag.String("annotationkey", "bln.space/podnat", "pod annotation key for iptables NAT trigger")
	httpPort = flag.Int("httpport", 8484, "http service port number")
	informerResync = flag.Int("informerresync", 0, "kubernetes informer resync interval")
	dryRun = flag.Bool("dryrun", false, "execute iptables commands or print only")
	restrictedPortsEnable = flag.Bool("restrictedportsenable", false, "allow to also NAT restricted ports like 22 or 6443")
	firewallFlavor = flag.String("firewallflavor", "iptables", "firewall implementation to use for NAT setup")
	resourcePrefix = flag.String("resourceprefix", "podnat", "resource prefix used for firewall chains and comments")
}

func main() {
	flag.Parse()

	events := make(chan *PodInfo)

	// skip update events - too noisy and not useful
	podInformer := NewPodInformer([]string{"add", "delete"}, events)
	go podInformer.Run()

	httpServer := NewHTTPServer(*httpPort)
	go httpServer.Run()

	switch *firewallFlavor {
	case "iptables":
		fw = NewIpTablesProcessor()
	default:
		fw = NewDummyProcessor()
	}

	// main loop: add/remove NAT entry for (dis)appearing pods
	for {
		podEvent := <-events
		_ = fw.Apply(podEvent)
		_ = fw.Reconcile()
	}
}
