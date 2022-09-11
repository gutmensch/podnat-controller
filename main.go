package main

import "flag"

var (
	annotation *string
	port       *int
)

func init() {
	annotation = flag.String("annotation", "bln.space/pod-nat", "pod annotation key for iptables NAT trigger")
	port = flag.Int("port", 8080, "http service port number")
}

func main() {
	flag.Parse()

	events := make(chan string)

	podInformer := NewPodInformer([]string{"add", "update", "delete"}, *annotation, events)
	go podInformer.Run()

	httpServer := NewHTTPServer(*port)
	go httpServer.Run()

	iptablesProcessor := NewIpTablesProcessor()
	for {
		podEvent := <-events
		iptablesProcessor.update(podEvent)
	}
}
