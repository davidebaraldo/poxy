// Comando poxy-client: proxy locale sulle macchine client. Inoltra tutto il
// traffico HTTP/HTTPS al poxy-server attraverso un tunnel mTLS multiplexato.
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sync"

	"github.com/hashicorp/yamux"

	"poxy/internal/tunnel"
)

func main() {
	var (
		bundlePath = flag.String("bundle", "", "percorso del bundle di provisioning (obbligatorio)")
		listen     = flag.String("listen", "127.0.0.1:8080", "indirizzo del proxy locale")
		installCA  = flag.Bool("install-ca", false, "installa la MITM CA del bundle come trusted root ed esci")
	)
	flag.Parse()

	if *bundlePath == "" {
		log.Fatal("serve -bundle <file.json>")
	}
	b, err := loadBundle(*bundlePath)
	if err != nil {
		log.Fatalf("bundle: %v", err)
	}

	if *installCA {
		if err := installRootCA(b.MITMCAPEM); err != nil {
			log.Fatalf("install-ca: %v", err)
		}
		log.Print("MITM CA installata come trusted root")
		return
	}

	tlsCfg, err := clientTLS(b)
	if err != nil {
		log.Fatalf("tls: %v", err)
	}
	mgr := &tunnelMgr{serverAddr: b.ServerAddr, tlsCfg: tlsCfg}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	if !isLoopbackListen(*listen) {
		log.Printf("ATTENZIONE: proxy locale su %s (non-loopback) e senza autenticazione: chiunque in rete puo' instradare traffico nel tunnel con la tua identita'. Usa un indirizzo loopback.", *listen)
	}
	log.Printf("proxy locale su %s -> tunnel %s", *listen, b.ServerAddr)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatalf("accept: %v", err)
		}
		go handle(c, mgr)
	}
}

func loadBundle(path string) (tunnel.Bundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return tunnel.Bundle{}, err
	}
	var b tunnel.Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return tunnel.Bundle{}, err
	}
	if b.ServerAddr == "" {
		return tunnel.Bundle{}, fmt.Errorf("bundle senza serverAddr")
	}
	return b, nil
}

func clientTLS(b tunnel.Bundle) (*tls.Config, error) {
	cert, err := tls.X509KeyPair([]byte(b.ClientCertPEM), []byte(b.ClientKeyPEM))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(b.TunnelCAPEM)) {
		return nil, fmt.Errorf("tunnel CA non valida")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   tunnel.ServerName,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// tunnelMgr mantiene una sessione yamux verso il server, riconnettendo quando
// necessario.
type tunnelMgr struct {
	serverAddr string
	tlsCfg     *tls.Config
	mu         sync.Mutex
	sess       *yamux.Session
}

func (m *tunnelMgr) stream() (net.Conn, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sess == nil || m.sess.IsClosed() {
		if err := m.dial(); err != nil {
			return nil, err
		}
	}
	st, err := m.sess.Open()
	if err != nil {
		if err := m.dial(); err != nil {
			return nil, err
		}
		return m.sess.Open()
	}
	return st, nil
}

func (m *tunnelMgr) dial() error {
	conn, err := tls.Dial("tcp", m.serverAddr, m.tlsCfg)
	if err != nil {
		return err
	}
	sess, err := yamux.Client(conn, nil)
	if err != nil {
		conn.Close()
		return err
	}
	m.sess = sess
	return nil
}

func handle(c net.Conn, mgr *tunnelMgr) {
	defer c.Close()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	if req.Method == http.MethodConnect {
		handleConnect(c, br, req, mgr)
		return
	}
	handlePlain(c, br, req, mgr)
}

func handleConnect(c net.Conn, br *bufio.Reader, req *http.Request, mgr *tunnelMgr) {
	host := ensurePort(req.URL.Host, "443")
	st, err := mgr.stream()
	if err != nil {
		writeGatewayError(c, err)
		return
	}
	defer st.Close()
	if err := tunnel.WritePreamble(st, tunnel.ModeTLS, host); err != nil {
		return
	}
	io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")

	// Alla fine di una direzione, chiude entrambi i lati per sbloccare l'altra
	// copia, poi attende che entrambe le goroutine terminino (niente troncamento
	// prematuro perché non si ritorna finché entrambe non hanno finito).
	done := make(chan struct{}, 2)
	go func() { io.Copy(st, br); st.Close(); c.Close(); done <- struct{}{} }()
	go func() { io.Copy(c, st); c.Close(); st.Close(); done <- struct{}{} }()
	<-done
	<-done
}

func isLoopbackListen(addr string) bool {
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

func handlePlain(c net.Conn, br *bufio.Reader, req *http.Request, mgr *tunnelMgr) {
	for {
		host := req.URL.Host
		if host == "" {
			host = req.Host
		}
		host = ensurePort(host, "80")

		st, err := mgr.stream()
		if err != nil {
			writeGatewayError(c, err)
			return
		}
		if err := tunnel.WritePreamble(st, tunnel.ModeHTTP, host); err != nil {
			st.Close()
			return
		}
		if err := req.Write(st); err != nil {
			st.Close()
			return
		}
		if _, err := io.Copy(c, st); err != nil {
			st.Close()
			return
		}
		st.Close()

		req, err = http.ReadRequest(br)
		if err != nil {
			return
		}
	}
}

func writeGatewayError(c net.Conn, err error) {
	body := "poxy-client: tunnel non disponibile: " + err.Error() + "\n"
	fmt.Fprintf(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
}

func ensurePort(hostport, def string) string {
	if _, _, err := net.SplitHostPort(hostport); err == nil {
		return hostport
	}
	return net.JoinHostPort(hostport, def)
}

// installRootCA installa la MITM CA come trusted root. Su Windows usa certutil
// (richiede privilegi di amministratore).
func installRootCA(pem string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("installazione automatica supportata solo su Windows; installa manualmente la MITM CA come trusted root")
	}
	f, err := os.CreateTemp("", "poxy-mitm-*.crt")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(pem); err != nil {
		f.Close()
		return err
	}
	f.Close()
	cmd := exec.Command("certutil", "-addstore", "-f", "Root", f.Name())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}
	return nil
}
