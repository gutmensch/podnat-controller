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
	stateURI              *string
	stateFlavor           *string
	fwProc                FirewallProcessor
)

func init() {
	annotationKey = flag.String("annotationkey", "bln.space/podnat", "pod annotation key for iptables NAT trigger")
	httpPort = flag.Int("httpport", 8484, "http service port number")
	informerResync = flag.Int("informerresync", 180, "kubernetes informer resync interval")
	dryRun = flag.Bool("dryrun", false, "execute iptables commands or print only")
	restrictedPorts = []uint16{22, 53, 6443}
	restrictedPortsEnable = flag.Bool("restrictedportsenable", false, "allow to also NAT restricted ports like 22 or 6443")
	firewallFlavor = flag.String("firewallflavor", "iptables", "firewall implementation to use for NAT setup")
	resourcePrefix = flag.String("resourceprefix", "podnat", "resource prefix used for firewall chains and comments")
	stateURI = flag.String("stateuri", "http://podnat-state-store:80", "uri for state store")
	stateFlavor = flag.String("stateflavor", "webdav", "which state storage to use, e.g. webdav")
}

func main() {
	flag.Parse()

	events := make(chan *PodInfo)

	podInformer := NewPodInformer([]string{"add", "update", "delete"}, *informerResync, events)
	go podInformer.Run()

	httpServer := NewHTTPServer(*httpPort)
	go httpServer.Run()

	switch *firewallFlavor {
	case "iptables":
		// XXX: with iptables we need some remote state to survive pod/node restarts
		// currently only side deployment with volume (webdav) supported
		var remoteState RemoteStateStore
		switch *stateFlavor {
		default:
			remoteState = NewWebDavState(*stateURI, "", "")
		}
		fwProc = NewIpTablesProcessor(remoteState)
	default:
		fwProc = NewDummyProcessor()
	}

	// main loop: add/remove NAT entry for (dis)appearing pods
	for {
		podNatEvent := <-events
		_ = fwProc.Apply(podNatEvent)
	}
}
