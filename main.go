package main

import (
	"flag"

	"k8s.io/klog/v2"
)

var (
	annotationKey         *string
	httpPort              *int
	informerResync        *int
	dryRun                *bool
	restrictedPorts       *string
	firewallFlavor        *string
	iptablesJump          *string
	excludeFilterNetworks *string
	includeFilterNetworks *string
	resourcePrefix        *string
	stateFlavor           *string
	stateURI              *string
	fwProc                FirewallProcessor
)

func init() {
	annotationKey = flag.String("annotationkey", "bln.space/podnat", "pod annotation key for iptables NAT trigger")
	httpPort = flag.Int("httpport", 8484, "http service port number")
	informerResync = flag.Int("informerresync", 180, "kubernetes informer resync interval")
	dryRun = flag.Bool("dryrun", false, "execute iptables commands or print only")
	restrictedPorts = flag.String("restrictedports", "22,53,6443", "restricted ports refused for NAT rule")
	firewallFlavor = flag.String("firewallflavor", "iptables", "firewall implementation to use for NAT setup")
	iptablesJump = flag.String("iptablesjump", "-2:-2:-2", "rule pos for chain jump to podnat (FORWARD:PREROUTING:POSTROUTING)")
	includeFilterNetworks = flag.String("inclfilternet", "", "disable networks during auto detection")
	excludeFilterNetworks = flag.String("exclfilternet", "", "enable networks during auto detection (e.g. RFC1918)")
	resourcePrefix = flag.String("resourceprefix", "podnat", "resource prefix used for firewall chains and comments")
	stateFlavor = flag.String("stateflavor", "webdav", "which state storage to use, e.g. webdav")
	stateURI = flag.String("stateuri", "http://podnat-state-store:80", "uri for state store")
}

func main() {
	klog.InitFlags(nil)
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
