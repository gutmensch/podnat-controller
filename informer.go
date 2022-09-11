package main

import (
	"fmt"
	"time"

	"github.com/golang/glog"
	"golang.org/x/exp/slices"

	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

type PodInformer struct {
	factory kubeinformers.SharedInformerFactory
}

func (i *PodInformer) Run() {
	stop := make(chan struct{})
	defer close(stop)
	i.factory.Start(stop)
	for {
		time.Sleep(time.Second)
	}
}

func NewPodInformer(subscriber []string, annotation string, events chan<- string) *PodInformer {
	config, err := clientcmd.BuildConfigFromFlags("", "")
	if err != nil {
		glog.Errorln(err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		glog.Errorln(err)
	}

	in := &PodInformer{
		factory: kubeinformers.NewSharedInformerFactory(clientset, time.Second*30),
	}
	podInformer := in.factory.Core().V1().Pods().Informer()

	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			// XXX: add check for annotation
			if slices.Contains(subscriber, "add") {
				glog.Infof("pod added: %s \n", obj)
				events <- fmt.Sprintf("%v\n", obj)
			}
		},
		DeleteFunc: func(obj interface{}) {
			if slices.Contains(subscriber, "delete") {
				glog.Infof("pod deleted: %s \n", obj)
				events <- fmt.Sprintf("%v\n", obj)
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			if slices.Contains(subscriber, "update") {
				glog.Infof("pod updated: old: %s, new: %s \n", oldObj, newObj)
				events <- fmt.Sprintf("%v\n", newObj)
			}
		},
	})

	return in
}
