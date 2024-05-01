package http

import (
	"fmt"
	"github.com/gutmensch/podnat-controller/internal/common"
	"net/http"

	"k8s.io/klog/v2"
)

type httpServer struct {
	port int
	mux  *http.ServeMux
}

func liveness(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "pong\n")
}

func generateNatEntryList(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "TODO: generate list of all current NAT entries\n")
}

func NewHTTPServer() *httpServer {
	server := &httpServer{
		port: *common.HTTPPort,
		mux:  http.NewServeMux(),
	}
	server.mux.HandleFunc("/healthz", liveness)
	server.mux.HandleFunc("/ping", liveness)
	server.mux.HandleFunc("/ready", liveness)
	server.mux.HandleFunc("/entries/list", generateNatEntryList)
	return server
}

func (s *httpServer) Run() {
	klog.Fatalln(http.ListenAndServe(fmt.Sprintf(":%d", s.port), s.mux))
}
