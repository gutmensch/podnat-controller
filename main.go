package main

import "fmt"

const ANNOTATION string = "bln.space/pod-nat"

func main() {
	events := make(chan string)

	podInformer := NewPodInformer([]string{"add", "update", "delete"}, ANNOTATION, events)
	go podInformer.Run()

	httpServer := NewHTTPServer()
	go httpServer.Run()

	iptablesProcessor := NewIpTablesProcessor()
	for {
		podEvent := <-events
		iptablesProcessor.update(podEvent)
		fmt.Println(podEvent)
	}
}
