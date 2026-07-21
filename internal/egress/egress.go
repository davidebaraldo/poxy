// Package egress esegue le richieste HTTP verso le destinazioni reali usando un
// fingerprint TLS unico (uTLS). Supporta sia HTTP/1.1 sia HTTP/2 in base
// all'ALPN negoziato, così il ClientHello resta autentico (offre h2+http/1.1).
package egress

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// profiles mappa le chiavi di configurazione ai ClientHelloID di uTLS.
var profiles = map[string]utls.ClientHelloID{
	"chrome":     utls.HelloChrome_Auto,
	"firefox":    utls.HelloFirefox_Auto,
	"safari":     utls.HelloSafari_Auto,
	"edge":       utls.HelloEdge_Auto,
	"ios":        utls.HelloIOS_Auto,
	"android":    utls.HelloAndroid_11_OkHttp,
	"randomized": utls.HelloRandomizedALPN,
}

// Profiles restituisce l'elenco ordinato delle chiavi di fingerprint disponibili.
func Profiles() []string {
	return []string{"chrome", "firefox", "safari", "edge", "ios", "android", "randomized"}
}

func helloID(profile string) utls.ClientHelloID {
	if id, ok := profiles[profile]; ok {
		return id
	}
	return utls.HelloChrome_Auto
}

// Egress instrada le richieste in uscita e riusa le connessioni HTTP/2.
type Egress struct {
	dialer *net.Dialer
	h2     *http2.Transport

	allowPrivate atomic.Bool

	mu      sync.Mutex
	h2conns map[string]*http2.ClientConn // chiave: host:port|profilo
}

// New crea un Egress.
func New() *Egress {
	e := &Egress{
		dialer: &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second},
		// ReadIdleTimeout/PingTimeout rilevano le connessioni h2 morte così il
		// pool non serve più richieste su socket zombie. DisableCompression:
		// evita l'auto-injection di "Accept-Encoding: gzip" (tell di fingerprint)
		// e mantiene il passthrough del body così com'è.
		h2: &http2.Transport{
			ReadIdleTimeout:    30 * time.Second,
			PingTimeout:        15 * time.Second,
			DisableCompression: true,
		},
		h2conns: make(map[string]*http2.ClientConn),
	}
	// Blocca per default i dial verso IP privati/loopback/link-local (anti-SSRF).
	// Il Control scatta DOPO la risoluzione DNS, quindi neutralizza il DNS rebinding.
	e.dialer.Control = e.control
	return e
}

// control è invocato dal Dialer con l'indirizzo IP risolto prima della connect.
func (e *Egress) control(_, address string, _ syscall.RawConn) error {
	if e.allowPrivate.Load() {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}
	if isBlockedIP(ip) {
		return fmt.Errorf("egress: destinazione %s in rete privata/riservata bloccata (abilita allowPrivate per consentirla)", ip)
	}
	return nil
}

func isBlockedIP(ip net.IP) bool {
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified()
}

// RoundTrip esegue req verso la destinazione reale. req deve essere in forma
// client (URL assoluto con Scheme+Host, RequestURI vuoto). profile seleziona il
// fingerprint TLS per lo scheme https. allowPrivate consente i dial verso reti
// private (default: bloccati).
func (e *Egress) RoundTrip(ctx context.Context, req *http.Request, profile string, allowPrivate bool) (*http.Response, error) {
	e.allowPrivate.Store(allowPrivate)
	if req.URL.Scheme == "http" {
		return e.roundTripPlain(ctx, req)
	}
	return e.roundTripTLS(ctx, req, profile)
}

func addrOf(u *url.URL) string {
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}
	return net.JoinHostPort(host, port)
}

func hasBody(req *http.Request) bool {
	return req.Body != nil && req.Body != http.NoBody && req.ContentLength != 0
}

// roundTripPlain gestisce lo scheme http (nessun TLS in uscita).
func (e *Egress) roundTripPlain(ctx context.Context, req *http.Request) (*http.Response, error) {
	conn, err := e.dialer.DialContext(ctx, "tcp", addrOf(req.URL))
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	req.Close = true
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, err
	}
	resp.Body = &connBody{ReadCloser: resp.Body, conn: conn}
	return resp, nil
}

// roundTripTLS gestisce lo scheme https con uTLS + h1/h2.
func (e *Egress) roundTripTLS(ctx context.Context, req *http.Request, profile string) (*http.Response, error) {
	addr := addrOf(req.URL)
	key := addr + "|" + profile
	body := hasBody(req)

	// Prova a riusare una connessione HTTP/2 esistente per lo stesso profilo.
	if cc := e.reuseH2(key); cc != nil {
		resp, err := cc.RoundTrip(req)
		if err == nil {
			return resp, nil
		}
		e.dropH2(key, cc)
		// Con un body la richiesta potrebbe essere stata consumata in parte:
		// non è ripetibile su una nuova connessione.
		if body {
			return nil, fmt.Errorf("egress: RoundTrip h2 su connessione riusata fallito, body non ripetibile: %w", err)
		}
	}

	uconn, alpn, err := e.dialTLS(ctx, req.URL.Hostname(), addr, profile)
	if err != nil {
		return nil, err
	}

	if alpn == "h2" {
		cc, err := e.h2.NewClientConn(uconn)
		if err != nil {
			uconn.Close()
			return nil, err
		}
		winner := e.storeH2(key, cc)
		if winner != cc {
			cc.Close() // un'altra goroutine ha già una conn valida: chiudi la nostra
		}
		resp, err := winner.RoundTrip(req)
		if err != nil {
			e.dropH2(key, winner)
			return nil, err
		}
		return resp, nil
	}

	// HTTP/1.1: una richiesta per connessione, poi chiusura.
	req.Close = true
	if err := req.Write(uconn); err != nil {
		uconn.Close()
		return nil, err
	}
	br := bufio.NewReader(uconn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		uconn.Close()
		return nil, err
	}
	resp.Body = &connBody{ReadCloser: resp.Body, conn: uconn}
	return resp, nil
}

// dialTLS stabilisce una connessione uTLS e restituisce l'ALPN negoziato.
func (e *Egress) dialTLS(ctx context.Context, sni, addr, profile string) (net.Conn, string, error) {
	raw, err := e.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, "", err
	}
	cfg := &utls.Config{ServerName: sni}
	uconn := utls.UClient(raw, cfg, helloID(profile))

	deadline := time.Now().Add(20 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = raw.SetDeadline(deadline)
	if err := uconn.Handshake(); err != nil {
		raw.Close()
		return nil, "", fmt.Errorf("egress: handshake TLS verso %s fallito: %w", addr, err)
	}
	// Dopo l'handshake applica la deadline complessiva della richiesta (se
	// presente), così un upstream che stalla non blocca la lettura per sempre.
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	} else {
		_ = raw.SetDeadline(time.Time{})
	}
	return uconn, uconn.ConnectionState().NegotiatedProtocol, nil
}

func (e *Egress) reuseH2(key string) *http2.ClientConn {
	e.mu.Lock()
	defer e.mu.Unlock()
	cc := e.h2conns[key]
	if cc != nil && cc.CanTakeNewRequest() {
		return cc
	}
	if cc != nil {
		delete(e.h2conns, key)
	}
	return nil
}

// storeH2 registra cc per key e restituisce la connessione da usare: se un'altra
// goroutine ha già registrato una connessione valida, restituisce quella (il
// chiamante deve chiudere cc).
func (e *Egress) storeH2(key string, cc *http2.ClientConn) *http2.ClientConn {
	e.mu.Lock()
	defer e.mu.Unlock()
	if ex := e.h2conns[key]; ex != nil && ex != cc && ex.CanTakeNewRequest() {
		return ex
	}
	e.h2conns[key] = cc
	return cc
}

func (e *Egress) dropH2(key string, cc *http2.ClientConn) {
	e.mu.Lock()
	if e.h2conns[key] == cc {
		delete(e.h2conns, key)
	}
	e.mu.Unlock()
	_ = cc.Close()
}

// connBody chiude la connessione sottostante alla chiusura del body (path h1).
type connBody struct {
	io.ReadCloser
	conn net.Conn
}

func (b *connBody) Close() error {
	err := b.ReadCloser.Close()
	b.conn.Close()
	return err
}
