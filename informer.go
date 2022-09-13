package main

import (
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

type PodInfo struct {
	Name       string
	Node       string
	Annotation *PodNatAnnotation
	IPv4       string
	IPv6       string
}

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

func generatePodInfo(data interface{}) *PodInfo {
	pod := data.(*corev1.Pod)
	podName := pod.ObjectMeta.Name
	podAnnotation, err := parseAnnotation(pod.ObjectMeta.Annotations[*annotation])
	if err != nil {
		glog.Errorf("ignoring pod %s with invalid annotation, error: '%v'\n", podName, err)
		return nil
	}
	info := &PodInfo{
		Name:       podName,
		Node:       shortHostName(pod.Spec.NodeName),
		Annotation: podAnnotation,
		IPv4:       pod.Status.PodIP,
		// TODO IPv6 support
		IPv6: "",
	}
	return info
}

func filterForAnnotationAndPlacement(data interface{}) bool {
	pod := data.(*corev1.Pod)
	if _, ok := pod.ObjectMeta.Annotations[*annotation]; ok {
		if shortHostName(pod.Spec.NodeName) == getEnv("HOSTNAME", "") {
			return true
		}
	}
	return false
}

func NewPodInformer(subscriber []string, events chan<- *PodInfo) *PodInformer {
	kubeconfig := getEnv("KUBECONFIG", "")
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		glog.Errorln(err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		glog.Errorln(err)
	}

	in := &PodInformer{
		factory: kubeinformers.NewSharedInformerFactory(clientset, time.Duration(*resync)*time.Second),
	}
	in.factory.Core().V1().Pods().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if slices.Contains(subscriber, "add") && filterForAnnotationAndPlacement(obj) {
				pod := generatePodInfo(obj)
				if pod != nil {
					glog.Infof("pod added and matched: %s \n", pod.Name)
					events <- pod
				}
			}
		},
		DeleteFunc: func(obj interface{}) {
			if slices.Contains(subscriber, "delete") && filterForAnnotationAndPlacement(obj) {
				pod := generatePodInfo(obj)
				if pod != nil {
					glog.Infof("pod deleted and matched: %s \n", pod.Name)
					events <- pod
				}
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			if slices.Contains(subscriber, "update") && filterForAnnotationAndPlacement(newObj) {
				pod := generatePodInfo(newObj)
				if pod != nil {
					glog.Infof("pod updated and matched: %s \n", pod.Name)
					events <- pod
				}
			}
		},
	})

	return in
}
