package main

import "flag"

var (
	annotation *string
	port       *int
	resync     *int
	dryRun     *bool
)

func init() {
	annotation = flag.String("annotation", "bln.space/podnat", "pod annotation key for iptables NAT trigger")
	port = flag.Int("port", 8484, "http service port number")
	resync = flag.Int("resync", 0, "kubernetes informer resync interval")
	dryRun = flag.Bool("dryrun", false, "execute iptables commands or print only")
	// logtostderr added by glog - set to true for console logging
}

func main() {
	flag.Parse()

	events := make(chan *PodInfo)

	podInformer := NewPodInformer([]string{"add", "delete"}, events)
	go podInformer.Run()

	httpServer := NewHTTPServer(*port)
	go httpServer.Run()

	iptablesProcessor := NewIpTablesProcessor()
	for {
		podEvent := <-events
		iptablesProcessor.update(podEvent)
	}
}
