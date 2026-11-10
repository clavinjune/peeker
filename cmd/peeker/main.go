package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/clavinjune/peeker/internal/agentskill"
	"github.com/clavinjune/peeker/internal/explorer"
	"github.com/clavinjune/peeker/web"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "skills" {
		if err := installSkill(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}
	listen := flag.String("listen", "127.0.0.1:8080", "Loopback listen address")
	proxy := flag.String("proxy", os.Getenv("KUBECTL_PROXY_URL"), "Use an external loopback proxy instead of managing contexts")
	expectIstio := flag.Bool("expect-istio", true, "Report pods without an istio-proxy sidecar")
	contextName := flag.String("context", "", "Start this kubeconfig context immediately")
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatal("unexpected arguments; use peeker skills add [--global] or peeker -h")
	}
	if err := run(*listen, *proxy, *contextName, *expectIstio); err != nil {
		log.Fatal(err)
	}
}

func installSkill(args []string) error {
	if len(args) == 0 || args[0] != "add" {
		return errors.New("usage: peeker skills add [--global]")
	}
	flags := flag.NewFlagSet("peeker skills add", flag.ContinueOnError)
	global := flags.Bool("global", false, "Install in ~/.agents/skills instead of the current directory")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: peeker skills add [--global]")
	}
	directory, err := os.Getwd()
	if *global {
		directory, err = os.UserHomeDir()
	}
	if err != nil {
		return err
	}
	path, err := agentskill.Install(directory)
	if err == nil {
		fmt.Println("Installed Peeker skill:", path)
	}
	return err
}

func run(listen, proxy, contextName string, expectIstio bool) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("listen must use a loopback IP address")
	}
	assets, err := fs.Sub(web.Assets, "dist")
	if err != nil {
		return err
	}
	manager := explorer.NewContextManager(assets)
	manager.Assessment.ExpectIstio = expectIstio
	defer manager.Close()
	if proxy != "" && contextName != "" {
		return errors.New("-context cannot be combined with an external proxy")
	}
	if contextName != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := manager.Select(ctx, contextName); err != nil {
			return err
		}
	}
	handler := manager.Handler()
	if proxy != "" {
		client, err := explorer.NewClient(proxy)
		if err != nil {
			return err
		}
		client.Assessment.ExpectIstio = expectIstio
		handler = explorer.Handler(client, assets)
	}
	server := &http.Server{Addr: listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	closed := make(chan struct{})
	go func() {
		<-ctx.Done()
		manager.Close()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdown)
		close(closed)
	}()
	log.Printf("Peeker at http://%s; read-only; cluster data in memory", listen)
	err = server.ListenAndServe()
	stop()
	<-closed
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
