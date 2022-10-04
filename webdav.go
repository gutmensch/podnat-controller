package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/golang/glog"
	"github.com/studio-b12/gowebdav"
)

type WebDAVState struct {
	Client    *gowebdav.Client
	Directory string
	File      string
	Mutex     sync.Mutex
}

func (s *WebDAVState) Put(data interface{}) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	jsonData, err := json.Marshal(data)
	if err != nil {
		return errors.New(fmt.Sprintf("could not encode data to json: %v\n", err))
	}
	if err = s.Client.Write(filepath.Join(s.Directory, s.File), jsonData, 0644); err != nil {
		return errors.New(fmt.Sprintf("could not write state: %v\n", err))
	}
	return nil
}

func (s *WebDAVState) Get() ([]byte, error) {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	bytes, err := s.Client.Read(filepath.Join(s.Directory, s.File))
	if err != nil {
		return nil, errors.New(fmt.Sprintf("could not read state: %v\n", err))
	}
	return bytes, nil
}

func (s *WebDAVState) init() error {
	if err := s.Client.Mkdir(s.Directory, 0644); err != nil {
		glog.Errorf("could not init state directory: %v\n", err)
		// EREMOTEIO
		os.Exit(121)
	}
	return nil
}

func NewWebDavState(URL, user, password string) *WebDAVState {
	state := &WebDAVState{
		Client:    gowebdav.NewClient(URL, user, password),
		Directory: getEnv("HOSTNAME", "node"),
		File:      "state.json",
	}

	state.init()

	return state
}
