// Package proxyserver implementa il lato server di poxy: accetta i tunnel mTLS
// dai client, intercetta (MITM) le connessioni TLS, riscrive gli header e
// instrada il traffico in uscita con un fingerprint TLS unico.
package proxyserver

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"

	"poxy/internal/certs"
	"poxy/internal/config"
	"poxy/internal/egress"
	"poxy/internal/traffic"
	"poxy/internal/tunnel"
)

// Server è il lato server di poxy.
type Server struct {
	cfg      *config.Store
	hub      *traffic.Hub
	egress   *egress.Egress
	registry *Registry

	tunnelCA *certs.CA
	mitmCA   *certs.CA

	// PublicTunnelAddr è l'indirizzo host:port pubblicizzato ai client nei bundle.
	PublicTunnelAddr string

	certMu    sync.RWMutex
	certCache map[string]*tls.Certificate
}

// New inizializza il server creando/caricando le CA nella dataDir.
func New(cfg *config.Store, hub *traffic.Hub, dataDir string) (*Server, error) {
	tunnelCA, err := certs.LoadOrCreateCA(
		filepath.Join(dataDir, "tunnel-ca.crt"),
		filepath.Join(dataDir, "tunnel-ca.key"),
		"poxy Tunnel CA",
	)
	if err != nil {
		return nil, err
	}
	mitmCA, err := certs.LoadOrCreateCA(
		filepath.Join(dataDir, "mitm-ca.crt"),
		filepath.Join(dataDir, "mitm-ca.key"),
		"poxy MITM CA",
	)
	if err != nil {
		return nil, err
	}
	return &Server{
		cfg:       cfg,
		hub:       hub,
		egress:    egress.New(),
		registry:  NewRegistry(),
		tunnelCA:  tunnelCA,
		mitmCA:    mitmCA,
		certCache: make(map[string]*tls.Certificate),
	}, nil
}

// Accessor usati dall'interfaccia web.
func (s *Server) Cfg() *config.Store      { return s.cfg }
func (s *Server) Hub() *traffic.Hub       { return s.hub }
func (s *Server) Clients() []ClientInfo   { return s.registry.List() }
func (s *Server) ClientCount() int        { return s.registry.Count() }
func (s *Server) MITMCAPEM() []byte       { return s.mitmCA.CertPEM }
func (s *Server) Profiles() []string      { return egress.Profiles() }

// TunnelTLSConfig costruisce la configurazione TLS per il listener del tunnel
// (mTLS: verifica il certificato client contro la Tunnel CA).
func (s *Server) TunnelTLSConfig() (*tls.Config, error) {
	certPEM, keyPEM, err := s.tunnelCA.IssueServerCert(tunnel.ServerName, []string{tunnel.ServerName}, nil)
	if err != nil {
		return nil, err
	}
	srvCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(s.tunnelCA.Cert)
	return &tls.Config{
		Certificates: []tls.Certificate{srvCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// IssueBundle crea un bundle di provisioning per un nuovo client.
func (s *Server) IssueBundle(name string) (tunnel.Bundle, error) {
	certPEM, keyPEM, err := s.tunnelCA.IssueClientCert(name)
	if err != nil {
		return tunnel.Bundle{}, err
	}
	return tunnel.Bundle{
		ServerAddr:    s.PublicTunnelAddr,
		Name:          name,
		TunnelCAPEM:   string(s.tunnelCA.CertPEM),
		ClientCertPEM: string(certPEM),
		ClientKeyPEM:  string(keyPEM),
		MITMCAPEM:     string(s.mitmCA.CertPEM),
	}, nil
}

// ServeTunnel accetta le connessioni del tunnel sul listener (già mTLS).
func (s *Server) ServeTunnel(l net.Listener) error {
	for {
		raw, err := l.Accept()
		if err != nil {
			return err
		}
		go s.handleTunnelConn(raw)
	}
}

func (s *Server) handleTunnelConn(raw net.Conn) {
	defer raw.Close()

	id := "unknown"
	if tc, ok := raw.(*tls.Conn); ok {
		if err := tc.Handshake(); err != nil {
			return
		}
		if st := tc.ConnectionState(); len(st.PeerCertificates) > 0 {
			id = st.PeerCertificates[0].Subject.CommonName
		}
	}
	addr := raw.RemoteAddr().String()
	entry := s.registry.Add(id, addr)
	defer s.registry.Remove(entry)

	session, err := yamux.Server(raw, nil)
	if err != nil {
		return
	}
	defer session.Close()

	for {
		stream, err := session.Accept()
		if err != nil {
			return
		}
		go s.handleStream(stream, entry)
	}
}

// bufConn presenta un net.Conn le cui letture passano da un bufio.Reader (per
// non perdere i byte già bufferizzati durante la lettura del preambolo).
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (s *Server) handleStream(stream net.Conn, entry *ClientEntry) {
	defer stream.Close()
	br := bufio.NewReader(stream)
	mode, target, err := tunnel.ReadPreamble(br)
	if err != nil {
		return
	}
	entry.streams.Add(1)
	defer entry.streams.Add(-1)

	bc := bufConn{Conn: stream, r: br}
	switch mode {
	case tunnel.ModeTLS:
		s.handleTLS(bc, target, entry)
	case tunnel.ModeHTTP:
		s.handleHTTP(bc, target, entry)
	case tunnel.ModeCtl:
		s.handleCtl(bc, target)
	}
}

// handleCtl serve il canale di controllo. "routes" -> lista dei pattern dominio
// che il client deve instradare nel tunnel.
func (s *Server) handleCtl(bc bufConn, target string) {
	if target == "routes" {
		_ = json.NewEncoder(bc).Encode(s.cfg.ProxiedPatterns())
	}
}

// handleTLS intercetta l'handshake TLS dell'app, presentando un certificato
// forgiato, poi serve le richieste HTTP in chiaro sopra al TLS terminato.
func (s *Server) handleTLS(bc bufConn, target string, entry *ClientEntry) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host, port = target, "443"
	}
	getCert := func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		name := hello.ServerName
		if name == "" {
			name = host
		}
		return s.forgeTLSCert(name)
	}
	tlsConn := tls.Server(bc, &tls.Config{
		GetCertificate: getCert,
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"http/1.1"},
	})
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	effHost := host
	if sni := tlsConn.ConnectionState().ServerName; sni != "" {
		effHost = sni
	}
	hostport := net.JoinHostPort(effHost, port)

	br := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		if !s.serveRequest(tlsConn, req, "https", effHost, hostport, entry) {
			return
		}
	}
}

// handleHTTP inoltra una singola richiesta HTTP in chiaro.
func (s *Server) handleHTTP(bc bufConn, target string, entry *ClientEntry) {
	req, err := http.ReadRequest(bc.r)
	if err != nil {
		return
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host, port = target, "80"
	}
	s.serveRequest(bc, req, "http", host, net.JoinHostPort(host, port), entry)
}

// serveRequest applica le regole, inoltra la richiesta e scrive la risposta.
// Restituisce true se la connessione può restare in keep-alive.
func (s *Server) serveRequest(w io.Writer, req *http.Request, scheme, host, hostport string, entry *ClientEntry) bool {
	start := time.Now()
	entry.reqs.Add(1)
	eff := s.cfg.Resolve(host)

	e := traffic.Entry{
		ID:          s.hub.NextID(),
		Time:        start,
		ClientID:    entry.ID,
		ClientAddr:  entry.Addr,
		Scheme:      scheme,
		Method:      req.Method,
		Host:        host,
		Path:        req.URL.RequestURI(),
		MatchedRule: eff.MatchedRule,
		Fingerprint: eff.Fingerprint,
	}
	reqWantsClose := req.Close || !req.ProtoAtLeast(1, 1)

	if eff.Blocked() {
		e.Blocked = true
		e.Status = http.StatusForbidden
		e.RespBytes = writeSimpleResponse(w, req, http.StatusForbidden, "poxy: dominio bloccato\n")
		e.DurationMs = sinceMs(start)
		s.hub.Publish(e)
		return false
	}

	// Trasforma la richiesta server in richiesta client per l'egress.
	// host è il solo hostname (regole/log); hostport porta la porta reale.
	req.URL.Scheme = scheme
	req.URL.Host = hostport
	req.RequestURI = ""
	removeHopByHop(req.Header)
	applyHeaders(req.Header, eff)
	e.UserAgent = req.Header.Get("User-Agent")
	e.ReqHeaders = cloneHeaders(req.Header)
	if req.ContentLength > 0 {
		e.ReqBytes = req.ContentLength
	}

	// Timeout complessivo: evita goroutine/connessioni appese su upstream che
	// stallano.
	ctx, cancel := context.WithTimeout(context.Background(), egressTimeout)
	defer cancel()
	req = req.WithContext(ctx)

	// Traccia il consumo del body per attendere che l'egress (inclusa la
	// goroutine di upload HTTP/2) lo abbia letto per intero prima di riusare la
	// connessione keep-alive: evita un secondo lettore concorrente del body.
	var tb *trackedBody
	if req.Body != nil && req.ContentLength != 0 {
		tb = &trackedBody{ReadCloser: req.Body, done: make(chan struct{})}
		req.Body = tb
	}

	resp, err := s.egress.RoundTrip(ctx, req, eff.Fingerprint, eff.AllowPrivate)
	if err != nil {
		e.Error = err.Error()
		e.Status = http.StatusBadGateway
		e.RespBytes = writeSimpleResponse(w, req, http.StatusBadGateway, "poxy: errore upstream: "+err.Error()+"\n")
		e.DurationMs = sinceMs(start)
		s.hub.Publish(e)
		return false
	}
	defer resp.Body.Close()

	removeHopByHop(resp.Header)
	// La risposta va all'app in HTTP/1.x: allinea il proto a quello della
	// richiesta dell'app (evita Transfer-Encoding chunked verso un HTTP/1.0).
	resp.ProtoMajor, resp.ProtoMinor = req.ProtoMajor, req.ProtoMinor
	resp.Proto = "HTTP/1.1"
	if req.ProtoMajor == 1 && req.ProtoMinor == 0 {
		resp.Proto = "HTTP/1.0"
	}
	// Framing verso il client: se la lunghezza è ignota (tipico delle risposte
	// h2/streaming), forza il chunked così il client rileva la fine del
	// messaggio senza attendere la chiusura della connessione (in keep-alive
	// non arriverebbe mai -> hang). Solo per risposte HTTP/1.1 con corpo.
	if req.ProtoAtLeast(1, 1) && len(resp.TransferEncoding) == 0 &&
		resp.ContentLength < 0 && bodyAllowed(resp.StatusCode, req.Method) {
		resp.TransferEncoding = []string{"chunked"}
	}
	respWantsClose := resp.Close
	e.Status = resp.StatusCode
	e.RespHeaders = cloneHeaders(resp.Header)

	cw := &countWriter{w: w}
	if err := resp.Write(cw); err != nil {
		e.Error = "write client: " + err.Error()
		e.RespBytes = cw.n
		e.DurationMs = sinceMs(start)
		s.hub.Publish(e)
		return false
	}

	// Attende che il body della richiesta sia stato letto per intero prima di
	// proseguire con la prossima richiesta keep-alive sulla stessa connessione.
	if tb != nil {
		select {
		case <-tb.done:
		case <-ctx.Done():
		}
	}

	e.RespBytes = cw.n
	e.DurationMs = sinceMs(start)
	s.hub.Publish(e)

	return !reqWantsClose && !respWantsClose
}

// egressTimeout è il tetto complessivo per una richiesta proxata.
const egressTimeout = 5 * time.Minute

// trackedBody segnala su done quando il body è stato letto interamente (EOF) o
// chiuso, così serveRequest può attendere il completamento dell'upload.
type trackedBody struct {
	io.ReadCloser
	done chan struct{}
	once sync.Once
}

func (b *trackedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.signal()
	}
	return n, err
}

func (b *trackedBody) Close() error {
	err := b.ReadCloser.Close()
	b.signal()
	return err
}

func (b *trackedBody) signal() { b.once.Do(func() { close(b.done) }) }

func (s *Server) forgeTLSCert(name string) (*tls.Certificate, error) {
	s.certMu.RLock()
	c, ok := s.certCache[name]
	s.certMu.RUnlock()
	if ok {
		return c, nil
	}
	certPEM, keyPEM, err := s.mitmCA.ForgeLeafPEM(name)
	if err != nil {
		return nil, err
	}
	tc, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	s.certMu.Lock()
	// L'hostname è scelto dal client del tunnel: limita la cache per evitare
	// crescita illimitata (memory DoS). Oltre il tetto si smette di cachare.
	if len(s.certCache) < maxCertCache {
		s.certCache[name] = &tc
	}
	s.certMu.Unlock()
	return &tc, nil
}

// maxCertCache limita il numero di certificati MITM forgiati tenuti in cache.
const maxCertCache = 4096

// hopByHop elenca gli header hop-by-hop, mai inoltrati end-to-end.
var hopByHop = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func removeHopByHop(h http.Header) {
	// Rimuove anche gli header nominati dall'header Connection.
	for _, name := range strings.Split(h.Get("Connection"), ",") {
		if n := strings.TrimSpace(name); n != "" {
			h.Del(n)
		}
	}
	for _, k := range hopByHop {
		h.Del(k)
	}
}

// fingerprintHeaders sono header che identificano il client (browser/OS/locale/
// hardware). Rimossi quando NormalizeFingerprint è attivo, così i client dietro
// poxy risultano indistinguibili tra loro. Non include header funzionali
// (Cookie, Authorization, Content-Type, Accept, Accept-Encoding).
var fingerprintHeaders = []string{
	// Client Hints
	"Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform", "Sec-Ch-Ua-Platform-Version",
	"Sec-Ch-Ua-Arch", "Sec-Ch-Ua-Model", "Sec-Ch-Ua-Bitness", "Sec-Ch-Ua-Full-Version",
	"Sec-Ch-Ua-Full-Version-List", "Sec-Ch-Ua-Wow64",
	"Sec-Ch-Prefers-Color-Scheme", "Sec-Ch-Prefers-Reduced-Motion",
	// Fetch metadata
	"Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-Fetch-User",
	// Preferenze / privacy signals
	"Accept-Language", "Dnt", "Sec-Gpc", "Upgrade-Insecure-Requests", "Priority",
	// Network/device hints
	"Device-Memory", "Downlink", "Ect", "Rtt", "Save-Data", "Viewport-Width", "Width",
}

// leakHeaders rivelano l'IP/rete del client o legano l'identità (X-Client-Data
// = field-trials/stato Google di Chrome). Rimossi SEMPRE: non devono mai
// raggiungere la destinazione, indipendentemente dalla config.
var leakHeaders = []string{
	"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port",
	"X-Original-Forwarded-For", "Forwarded", "Via",
	"X-Real-IP", "X-Client-IP", "Client-IP", "CF-Connecting-IP", "True-Client-IP",
	"X-Client-Data",
}

func applyHeaders(h http.Header, eff config.Effective) {
	for _, name := range leakHeaders {
		h.Del(name)
	}
	if eff.NormalizeFingerprint {
		for _, name := range fingerprintHeaders {
			h.Del(name)
		}
	}
	for _, name := range eff.StripHeaders {
		h.Del(name)
	}
	for k, v := range eff.SetHeaders {
		h.Set(k, v)
	}
	if eff.UserAgent != "" {
		h.Set("User-Agent", eff.UserAgent)
	}
}

func writeSimpleResponse(w io.Writer, req *http.Request, code int, body string) int64 {
	resp := &http.Response{
		StatusCode:    code,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"text/plain; charset=utf-8"}, "Connection": {"close"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Close:         true,
		Request:       req,
	}
	cw := &countWriter{w: w}
	_ = resp.Write(cw)
	return cw.n
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

func sinceMs(t time.Time) int64 { return time.Since(t).Milliseconds() }

// cloneHeaders copia gli header per lo snapshot di traffico (senza tenere
// riferimenti alla mappa viva della richiesta/risposta).
func cloneHeaders(h http.Header) map[string][]string {
	out := make(map[string][]string, len(h))
	for k, v := range h {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// bodyAllowed indica se una risposta con questo status/metodo può avere un corpo.
func bodyAllowed(status int, method string) bool {
	if method == http.MethodHead {
		return false
	}
	if status/100 == 1 || status == http.StatusNoContent || status == http.StatusNotModified {
		return false
	}
	return true
}
