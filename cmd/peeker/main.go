package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/clavinjune/peeker/internal/explorer"
)

func main() {
	proxy := os.Getenv("KUBECTL_PROXY_URL")
	if proxy == "" {
		proxy = "http://127.0.0.1:8001"
	}
	listen := flag.String("listen", "127.0.0.1:8080", "Loopback listen address")
	static := flag.String("static", "web/dist", "Built frontend directory")
	flag.Parse()
	host, _, err := net.SplitHostPort(*listen)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		log.Fatal("listen must use a loopback IP address")
	}
	client, err := explorer.NewClient(proxy)
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Addr: *listen, Handler: explorer.Handler(client, *static), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024}
	log.Printf("Peeker at http://%s; read-only; memory only; proxy %s", *listen, proxy)
	log.Fatal(server.ListenAndServe())
}
