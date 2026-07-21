// Comando poxy-server: accetta i tunnel dai client, intercetta e instrada il
// traffico, e serve l'interfaccia web di amministrazione.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"poxy/internal/config"
	"poxy/internal/proxyserver"
	"poxy/internal/traffic"
	"poxy/internal/web"
)

func main() {
	var (
		dataDir     = flag.String("data", "poxy-data", "directory dati (config, CA)")
		webAddr     = flag.String("web", "127.0.0.1:8080", "indirizzo interfaccia web")
		webCert     = flag.String("web-cert", "", "certificato TLS per il pannello web (abilita HTTPS)")
		webKey      = flag.String("web-key", "", "chiave TLS per il pannello web")
		webInsecure = flag.Bool("web-insecure", false, "consenti bind non-loopback del pannello senza TLS (sconsigliato)")
		tunnelAddr  = flag.String("tunnel", "0.0.0.0:9000", "indirizzo listener tunnel (mTLS)")
		publicAddr  = flag.String("public", "", "host:port pubblico del tunnel annunciato ai client (default = -tunnel)")
		quiet       = flag.Bool("quiet", false, "non stampare in console ogni richiesta proxata")
	)
	flag.Parse()

	cfg, err := config.Load(*dataDir + "/config.json")
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	if pw, err := web.EnsurePassword(cfg); err != nil {
		log.Fatalf("password: %v", err)
	} else if pw != "" {
		log.Printf("password web generata: %s  (cambiala dal pannello)", pw)
	}

	hub := traffic.NewHub(4000)
	if !*quiet {
		go logRequests(hub)
	}

	srv, err := proxyserver.New(cfg, hub, *dataDir)
	if err != nil {
		log.Fatalf("server: %v", err)
	}
	srv.PublicTunnelAddr = *publicAddr
	if srv.PublicTunnelAddr == "" {
		srv.PublicTunnelAddr = *tunnelAddr
	}
	if strings.HasPrefix(srv.PublicTunnelAddr, "0.0.0.0") {
		log.Printf("ATTENZIONE: -public non impostato; i bundle useranno %q (non raggiungibile). Imposta -public host:port.", srv.PublicTunnelAddr)
	}

	// Listener tunnel mTLS.
	tlsCfg, err := srv.TunnelTLSConfig()
	if err != nil {
		log.Fatalf("tls tunnel: %v", err)
	}
	ln, err := tls.Listen("tcp", *tunnelAddr, tlsCfg)
	if err != nil {
		log.Fatalf("listen tunnel: %v", err)
	}
	go func() {
		log.Printf("tunnel in ascolto su %s (mTLS)", *tunnelAddr)
		if err := srv.ServeTunnel(ln); err != nil {
			log.Fatalf("tunnel: %v", err)
		}
	}()

	// Interfaccia web.
	wsrv := web.New(srv)
	httpSrv := &http.Server{
		Addr:              *webAddr,
		Handler:           wsrv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	useTLS := *webCert != "" && *webKey != ""
	if !useTLS && !isLoopbackAddr(*webAddr) && !*webInsecure {
		log.Fatalf("web: bind non-loopback %q senza TLS. Fornisci -web-cert/-web-key, oppure -web-insecure per forzare (sconsigliato: password/bundle in chiaro).", *webAddr)
	}
	if useTLS {
		log.Printf("pannello web su https://%s", webAddr8080Host(*webAddr))
		if err := httpSrv.ListenAndServeTLS(*webCert, *webKey); err != nil {
			log.Fatalf("web: %v", err)
		}
	} else {
		log.Printf("pannello web su http://%s", webAddr8080Host(*webAddr))
		if err := httpSrv.ListenAndServe(); err != nil {
			log.Fatalf("web: %v", err)
		}
	}
}

// logRequests stampa in console ogni richiesta proxata, con i dettagli.
func logRequests(hub *traffic.Hub) {
	ch, _ := hub.Subscribe()
	for e := range ch {
		status := fmt.Sprintf("%d", e.Status)
		if e.Blocked {
			status = fmt.Sprintf("BLOCK(%d)", e.Status)
		}
		rule := e.MatchedRule
		if rule == "" {
			rule = "-"
		}
		line := fmt.Sprintf("%-14s %-6s %s://%s%s -> %s  fp=%s rule=%s up=%s down=%s %dms",
			e.ClientID, e.Method, e.Scheme, e.Host, e.Path, status,
			e.Fingerprint, rule, humanBytes(e.ReqBytes), humanBytes(e.RespBytes), e.DurationMs)
		if e.UserAgent != "" {
			line += fmt.Sprintf(" ua=%q", e.UserAgent)
		}
		if e.Error != "" {
			line += "  ERR=" + e.Error
		}
		log.Print(line)
	}
}

func humanBytes(n int64) string {
	const u = "KMGT"
	if n < 1024 {
		return fmt.Sprintf("%dB", n)
	}
	f := float64(n)
	i := -1
	for f >= 1024 && i < len(u)-1 {
		f /= 1024
		i++
	}
	return fmt.Sprintf("%.1f%cB", f, u[i])
}

func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func webAddr8080Host(addr string) string {
	if h, p, err := net.SplitHostPort(addr); err == nil && (h == "0.0.0.0" || h == "") {
		return net.JoinHostPort("127.0.0.1", p)
	}
	return addr
}
