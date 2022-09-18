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
	firewallProcessor     FirewallProcessor
)

func init() {
	annotationKey = flag.String("annotationKey", "bln.space/podnat", "pod annotation key for iptables NAT trigger")
	httpPort = flag.Int("httpPort", 8484, "http service port number")
	informerResync = flag.Int("informerResync", 0, "kubernetes informer resync interval")
	dryRun = flag.Bool("dryRun", false, "execute iptables commands or print only")
	restrictedPortsEnable = flag.Bool("restrictedPortsEnable", false, "allow to also NAT restricted ports like 22 or 6443")
	firewallFlavor = flag.String("firewallFlavor", "iptables", "firewall implementation to use for NAT setup")
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
		firewallProcessor = NewIpTablesProcessor()
	}

	for {
		podEvent := <-events
		_ = firewallProcessor.apply(podEvent)
	}
}
