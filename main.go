package main

import "flag"

var (
	annotationKey   *string
	httpPort        *int
	informerResync  *int
	dryRun          *bool
	restrictedPorts *string
	firewallFlavor  *string
	excludeNetworks *string
	includeNetworks *string
	resourcePrefix  *string
	stateFlavor     *string
	stateURI        *string
	fwProc          FirewallProcessor
)

func init() {
	annotationKey = flag.String("annotationkey", "bln.space/podnat", "pod annotation key for iptables NAT trigger")
	httpPort = flag.Int("httpport", 8484, "http service port number")
	informerResync = flag.Int("informerresync", 180, "kubernetes informer resync interval")
	dryRun = flag.Bool("dryrun", false, "execute iptables commands or print only")
	restrictedPorts = flag.String("restrictedports", "22,53,6443", "restricted ports refused for NAT rule")
	firewallFlavor = flag.String("firewallflavor", "iptables", "firewall implementation to use for NAT setup")
	includeNetworks = flag.String("includenetworks", "", "include networks for auto detection (e.g. internal RFC1918 ones)")
	excludeNetworks = flag.String("excludenetworks", "", "exclude networks for auto detection")
	resourcePrefix = flag.String("resourceprefix", "podnat", "resource prefix used for firewall chains and comments")
	stateFlavor = flag.String("stateflavor", "webdav", "which state storage to use, e.g. webdav")
	stateURI = flag.String("stateuri", "http://podnat-state-store:80", "uri for state store")
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
		// XXX: with iptables we need a remote state to survive pod/node restarts
		var remoteState StateStore
		switch *stateFlavor {
		default:
			remoteState = NewWebDavState(*stateURI, "", "")
		}
		fwProc = NewIpTablesProcessor(remoteState)
	default:
		fwProc = NewDummyProcessor()
	}

	for {
		podNatEvent := <-events
		_ = fwProc.Apply(podNatEvent)
	}
}
