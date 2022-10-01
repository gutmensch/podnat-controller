package main

type RemoteStateStore interface {
	Get() ([]byte, error)
	Put(data interface{}) error
}
