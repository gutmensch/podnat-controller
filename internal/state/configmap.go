package state

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gutmensch/podnat-controller/internal/common"
	corev1 "k8s.io/api/core/v1"
	"os"
	"sync"

	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
)

type ConfigMapState struct {
	Client    *kubernetes.Clientset
	Name      string
	Namespace string
	Mutex     sync.Mutex
}

func (s *ConfigMapState) Put(data interface{}) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	var err error
	var jsonData []byte
	jsonData, err = json.Marshal(data)
	if err != nil {
		return errors.New(fmt.Sprintf("could not encode data to json: %v\n", err))
	}

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: s.Name,
		},
		Data: map[string]string{
			"state.json": string(jsonData),
		},
	}

	if _, err = s.Client.CoreV1().ConfigMaps(s.Namespace).Get(context.TODO(), s.Name, metav1.GetOptions{}); k8serr.IsNotFound(err) {
		klog.V(9).Infof("creating configmap %s", s.Name)
		_, err = s.Client.CoreV1().ConfigMaps(s.Namespace).Create(context.TODO(), configMap, metav1.CreateOptions{})
	} else {
		klog.V(9).Infof("updating existing configmap %s", s.Name)
		_, err = s.Client.CoreV1().ConfigMaps(s.Namespace).Update(context.TODO(), configMap, metav1.UpdateOptions{})
	}

	return err
}

func (s *ConfigMapState) Get() ([]byte, error) {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	var configMap *corev1.ConfigMap
	var err error
	var exists bool

	configMap, err = s.Client.CoreV1().ConfigMaps(s.Namespace).Get(context.TODO(), s.Name, metav1.GetOptions{})

	if k8serr.IsNotFound(err) {
		klog.Warningf("configmap %s in namespace %s not found, error: '%v'\n", s.Name, s.Namespace, err)
		goto ExitWithError
	}

	if statusError, isStatus := err.(*k8serr.StatusError); isStatus {
		klog.Warningf("error getting configmap: %v\n", statusError.ErrStatus.Message)
		goto ExitWithError
	}

	if _, exists = configMap.Data["state.json"]; exists {
		return []byte(configMap.Data["state.json"]), nil
	}

ExitWithError:
	return []byte(""), err
}

func NewConfigMapState() *ConfigMapState {
	kubeConfig := common.GetEnv("KUBECONFIG", "")
	var config *rest.Config
	var clientSet *kubernetes.Clientset
	var err error
	config, err = clientcmd.BuildConfigFromFlags("", kubeConfig)
	if err != nil {
		klog.Errorln(err)
		os.Exit(1)
	}

	clientSet, err = kubernetes.NewForConfig(config)
	if err != nil {
		klog.Errorln(err)
		os.Exit(1)
	}

	state := &ConfigMapState{
		Client:    clientSet,
		Name:      fmt.Sprintf("podnat-controller-%s", common.NodeID),
		Namespace: common.GetEnv("NAMESPACE", "podnat-controller-system"),
	}

	return state
}
