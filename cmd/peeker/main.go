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
	stdio := flag.Bool("mcp", false, "Run MCP over stdin/stdout; defaults to the current kubeconfig context")
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatal("unexpected arguments; use peeker skills add [--global] or peeker -h")
	}
	if err := run(*listen, *proxy, *contextName, *expectIstio, *stdio); err != nil {
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

func clusterHandler(ctx context.Context, assets fs.FS, proxy, contextName string, expectIstio bool) (http.Handler, func(), error) {
	manager := explorer.NewContextManager(assets)
	manager.Assessment.ExpectIstio = expectIstio
	if proxy != "" && contextName != "" {
		manager.Close()
		return nil, nil, errors.New("-context cannot be combined with an external proxy")
	}
	if contextName != "" {
		ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		if err := manager.Select(ctx, contextName); err != nil {
			manager.Close()
			return nil, nil, err
		}
	}
	if proxy != "" {
		manager.Close()
		client, err := explorer.NewClient(proxy)
		if err != nil {
			return nil, nil, err
		}
		client.Assessment.ExpectIstio = expectIstio
		return explorer.Handler(client, assets), client.Close, nil
	}
	return manager.Handler(), manager.Close, nil
}

func run(listen, proxy, contextName string, expectIstio, stdio bool) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if stdio && proxy == "" && contextName == "" {
		var err error
		contextName, err = explorer.CurrentContext(ctx)
		if err != nil {
			return err
		}
	}
	assets, err := fs.Sub(web.Assets, "dist")
	if err != nil {
		return err
	}
	handler, closeCluster, err := clusterHandler(ctx, assets, proxy, contextName, expectIstio)
	if err != nil {
		return err
	}
	defer closeCluster()
	if stdio {
		err := explorer.RunMCP(ctx, handler)
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("listen must use a loopback IP address")
	}
	server := &http.Server{Addr: listen, Handler: explorer.MCPHandler(handler), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024}
	closed := make(chan struct{})
	go func() {
		<-ctx.Done()
		closeCluster()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdown)
		close(closed)
	}()
	log.Printf("Peeker at http://%s; Explore read-only; Registry actions use peeker-responder; cluster data in memory", listen)
	err = server.ListenAndServe()
	stop()
	<-closed
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
