package main

import (
	"net"
	"os"
	"time"

	"github.com/golang/glog"
	"golang.org/x/exp/slices"

	corev1 "k8s.io/api/core/v1"

	"k8s.io/apimachinery/pkg/util/runtime"
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
	defer runtime.HandleCrash()
	i.factory.Start(stop)
	for {
		time.Sleep(time.Second)
	}
}

func generatePodInfo(event string, data interface{}) *PodInfo {
	pod := data.(*corev1.Pod)
	podName := pod.ObjectMeta.Name
	podNamespace := pod.ObjectMeta.Namespace
	podAnnotation, err := parseAnnotation(pod.ObjectMeta.Annotations[*annotationKey])
	if err != nil {
		glog.Warningf("ignoring pod %s with invalid annotation, error: '%v'\n", podName, err)
		return nil
	}

	info := &PodInfo{
		Event:      event,
		Name:       podName,
		Namespace:  podNamespace,
		Node:       shortHostName(pod.Spec.NodeName),
		Annotation: podAnnotation,
		IPv4:       parseIP(pod.Status.PodIP),
	}
	return info
}

func filterForAnnotationAndPlacement(event string, data interface{}) bool {
	pod := data.(*corev1.Pod)

	// IP not yet assigned, wait for next update cycle
	if net.ParseIP(pod.Status.PodIP) == nil {
		return false
	}

	// not running on this node
	if shortHostName(pod.Spec.NodeName) != getEnv("HOSTNAME", "") {
		return false
	}

	// pod not ready (also avoids noise during pod replacement updates)
	for _, cond := range pod.Status.Conditions {
		if cond.Type == "Ready" && cond.Status == "False" && event == "update" {
			return false
		}
	}

	// valid pod and state
	if _, ok := pod.ObjectMeta.Annotations[*annotationKey]; ok {
		return true
	}

	return false
}

func NewPodInformer(subscriber []string, resync int, events chan<- *PodInfo) *PodInformer {
	kubeconfig := getEnv("KUBECONFIG", "")
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		glog.Errorln(err)
		os.Exit(1)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		glog.Errorln(err)
		os.Exit(1)
	}

	in := &PodInformer{
		factory: kubeinformers.NewSharedInformerFactory(clientset, time.Duration(resync)*time.Second),
	}
	in.factory.Core().V1().Pods().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if slices.Contains(subscriber, "add") && filterForAnnotationAndPlacement("add", obj) {
				pod := generatePodInfo("add", obj)
				if pod != nil {
					glog.Warningf("new pod added, matched filters: %s \n", pod.Name)
					events <- pod
				}
			}
		},
		DeleteFunc: func(obj interface{}) {
			if slices.Contains(subscriber, "delete") && filterForAnnotationAndPlacement("delete", obj) {
				pod := generatePodInfo("delete", obj)
				if pod != nil {
					glog.Warningf("pod deleted, matched filters: %s \n", pod.Name)
					events <- pod
				}
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			if slices.Contains(subscriber, "update") && filterForAnnotationAndPlacement("update", newObj) {
				pod := generatePodInfo("update", newObj)
				if pod != nil {
					glog.Warningf("pod updated, matched filters: %s \n", pod.Name)
					events <- pod
				}
			}
		},
	})

	return in
}
