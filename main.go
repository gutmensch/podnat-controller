package main

import "flag"

var (
	annotation       *string
	httpPort         *int
	resync           *int
	dryRun           *bool
	restrictedEnable *bool
	restrictedPorts  = []uint16{22, 53, 6443}
)

func init() {
	annotation = flag.String("annotation", "bln.space/podnat", "pod annotation key for iptables NAT trigger")
	httpPort = flag.Int("port", 8484, "http service port number")
	resync = flag.Int("resync", 0, "kubernetes informer resync interval")
	dryRun = flag.Bool("dryrun", false, "execute iptables commands or print only")
	restrictedEnable = flag.Bool("restricted", false, "allow to also NAT restricted ports like 22 or 6443")
}

func main() {
	flag.Parse()

	events := make(chan *PodInfo)

	podInformer := NewPodInformer([]string{"add", "delete"}, events)
	go podInformer.Run()

	httpServer := NewHTTPServer(*httpPort)
	go httpServer.Run()

	iptablesProcessor := NewIpTablesProcessor()
	for {
		podEvent := <-events
		iptablesProcessor.update(podEvent)
	}
}
