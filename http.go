package main

import (
	"fmt"
	"net/http"

	"github.com/golang/glog"
)

type httpServer struct {
	mux *http.ServeMux
}

func liveness(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "pong\n")
}

func NewHTTPServer() *httpServer {
	server := &httpServer{
		mux: http.NewServeMux(),
	}
	server.mux.HandleFunc("/ping", liveness)
	server.mux.HandleFunc("/ready", liveness)
	return server
}

func (s *httpServer) Run() {
	glog.Fatalln(http.ListenAndServe(":8080", s.mux))
}
