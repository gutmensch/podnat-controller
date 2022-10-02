package main

type StateStore interface {
	Get() ([]byte, error)
	Put(data interface{}) error
}
