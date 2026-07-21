// Package web espone l'interfaccia di amministrazione di poxy: configurazione,
// gestione domini, stato dei client e traffico in tempo reale (SSE).
package web

import (
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"poxy/internal/config"
	"poxy/internal/proxyserver"
)

//go:embed static
var staticFS embed.FS

// Server serve l'interfaccia web.
type Server struct {
	ps *proxyserver.Server

	mu       sync.Mutex
	sessions map[string]time.Time // token -> scadenza

	loginMu    sync.Mutex
	loginFails map[string]*failState // ip -> stato tentativi
}

type failState struct {
	fails       int
	lockedUntil time.Time
}

// New crea il server web.
func New(ps *proxyserver.Server) *Server {
	return &Server{
		ps:         ps,
		sessions:   make(map[string]time.Time),
		loginFails: make(map[string]*failState),
	}
}

const maxBodyBytes = 1 << 20 // 1 MiB per le richieste JSON del pannello

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// EnsurePassword imposta una password iniziale casuale se non configurata,
// restituendo la password in chiaro generata (vuota se già presente).
func EnsurePassword(cfg *config.Store) (string, error) {
	snap := cfg.Snapshot()
	if snap.Web.PasswordHash != "" {
		return "", nil
	}
	buf := make([]byte, 9)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	pw := hex.EncodeToString(buf)
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	if err := cfg.Update(func(c *config.Config) { c.Web.PasswordHash = string(hash) }); err != nil {
		return "", err
	}
	return pw, nil
}

// Handler costruisce il router HTTP.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Endpoint pubblici (senza sessione).
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	mux.HandleFunc("GET /api/session", s.handleSession)

	// Endpoint protetti.
	mux.Handle("GET /api/config", s.auth(s.handleGetConfig))
	mux.Handle("PUT /api/config", s.auth(s.handlePutConfig))
	mux.Handle("GET /api/domains", s.auth(s.handleGetDomains))
	mux.Handle("PUT /api/domains", s.auth(s.handlePutDomains))
	mux.Handle("GET /api/fingerprints", s.auth(s.handleFingerprints))
	mux.Handle("GET /api/clients", s.auth(s.handleClients))
	mux.Handle("GET /api/stats", s.auth(s.handleStats))
	mux.Handle("GET /api/traffic", s.auth(s.handleTraffic))
	mux.Handle("GET /api/traffic/live", s.auth(s.handleTrafficLive))
	mux.Handle("POST /api/password", s.auth(s.handlePassword))
	mux.Handle("GET /ca.crt", s.auth(s.handleCA))
	mux.Handle("GET /api/bundle", s.auth(s.handleBundle))
	mux.Handle("GET /api/setup", s.auth(s.handleSetup))

	// Download del binario client: pubblico (non è un segreto; il bundle con la
	// chiave privata è invece incorporato nell'installer protetto da sessione).
	mux.HandleFunc("GET /download/poxy-client.exe", s.handleDownloadClient)

	// SPA statica.
	sub, _ := fs.Sub(staticFS, "static")
	mux.Handle("/", http.FileServer(http.FS(sub)))
	return mux
}

// --- Autenticazione ---

func (s *Server) auth(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.valid(r) {
			http.Error(w, "non autenticato", http.StatusUnauthorized)
			return
		}
		h(w, r)
	})
}

func (s *Server) valid(r *http.Request) bool {
	c, err := r.Cookie("poxy_session")
	if err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.sessions[c.Value]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(s.sessions, c.Value)
		return false
	}
	return true
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if s.loginLocked(ip) {
		http.Error(w, "troppi tentativi falliti, riprova più tardi", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "richiesta non valida", http.StatusBadRequest)
		return
	}
	hash := s.ps.Cfg().Snapshot().Web.PasswordHash
	if hash == "" || bcrypt.CompareHashAndPassword([]byte(hash), []byte(body.Password)) != nil {
		s.loginFail(ip)
		http.Error(w, "password errata", http.StatusUnauthorized)
		return
	}
	s.loginReset(ip)

	tok := newToken()
	s.mu.Lock()
	s.sweepSessions()
	s.sessions[tok] = time.Now().Add(12 * time.Hour)
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     "poxy_session",
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, map[string]bool{"ok": true})
}

// sweepSessions rimuove i token scaduti. Va chiamata tenendo s.mu.
func (s *Server) sweepSessions() {
	now := time.Now()
	for k, exp := range s.sessions {
		if now.After(exp) {
			delete(s.sessions, k)
		}
	}
}

func (s *Server) loginLocked(ip string) bool {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	st := s.loginFails[ip]
	return st != nil && time.Now().Before(st.lockedUntil)
}

func (s *Server) loginFail(ip string) {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	st := s.loginFails[ip]
	if st == nil {
		st = &failState{}
		s.loginFails[ip] = st
	}
	st.fails++
	// Dopo 5 tentativi falliti, lockout crescente (max 15 min).
	if st.fails >= 5 {
		backoff := time.Duration(st.fails-4) * time.Minute
		if backoff > 15*time.Minute {
			backoff = 15 * time.Minute
		}
		st.lockedUntil = time.Now().Add(backoff)
	}
}

func (s *Server) loginReset(ip string) {
	s.loginMu.Lock()
	delete(s.loginFails, ip)
	s.loginMu.Unlock()
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("poxy_session"); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "poxy_session", Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]bool{"authenticated": s.valid(r)})
}

func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var body struct {
		Old string `json:"old"`
		New string `json:"new"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.New) < 10 {
		http.Error(w, "nuova password troppo corta (min 10)", http.StatusBadRequest)
		return
	}
	hash := s.ps.Cfg().Snapshot().Web.PasswordHash
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(body.Old)) != nil {
		http.Error(w, "password attuale errata", http.StatusUnauthorized)
		return
	}
	nh, err := bcrypt.GenerateFromPassword([]byte(body.New), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "errore interno", http.StatusInternalServerError)
		return
	}
	if err := s.ps.Cfg().Update(func(c *config.Config) { c.Web.PasswordHash = string(nh) }); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// --- Config ed egress ---

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.ps.Cfg().Snapshot().Egress)
}

func (s *Server) handlePutConfig(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var ec config.EgressConfig
	if err := json.NewDecoder(r.Body).Decode(&ec); err != nil {
		http.Error(w, "richiesta non valida", http.StatusBadRequest)
		return
	}
	if ec.DefaultAction != config.ActionAllow && ec.DefaultAction != config.ActionBlock {
		ec.DefaultAction = config.ActionAllow
	}
	if err := s.ps.Cfg().Update(func(c *config.Config) { c.Egress = ec }); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, s.ps.Cfg().Snapshot().Egress)
}

func (s *Server) handleGetDomains(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.ps.Cfg().Snapshot().Domains)
}

func (s *Server) handlePutDomains(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
	var rules []config.DomainRule
	if err := json.NewDecoder(r.Body).Decode(&rules); err != nil {
		http.Error(w, "richiesta non valida", http.StatusBadRequest)
		return
	}
	if err := s.ps.Cfg().Update(func(c *config.Config) { c.Domains = rules }); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, s.ps.Cfg().Snapshot().Domains)
}

func (s *Server) handleFingerprints(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.ps.Profiles())
}

// --- Client, stats, traffico ---

func (s *Server) handleClients(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.ps.Clients())
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.ps.Hub().Snapshot(s.ps.ClientCount()))
}

func (s *Server) handleTraffic(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	writeJSON(w, s.ps.Hub().Recent(limit))
}

func (s *Server) handleTrafficLive(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming non supportato", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher.Flush()

	ch, cancel := s.ps.Hub().Subscribe()
	defer cancel()

	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case e := <-ch:
			data, err := json.Marshal(e)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

// --- Download CA e bundle client ---

func (s *Server) handleCA(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="poxy-mitm-ca.crt"`)
	w.Write(s.ps.MITMCAPEM())
}

func (s *Server) handleBundle(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "client"
	}
	bundle, err := s.ps.IssueBundle(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="poxy-%s.json"`, name))
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(bundle)
}

// handleSetup genera un installer PowerShell (Windows) con bundle e MITM CA
// incorporati: scarica il client, installa la CA, imposta proxy e avvio automatico.
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "client"
	}
	bundle, err := s.ps.IssueBundle(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	bundleJSON, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	script := strings.NewReplacer(
		"__BUNDLE__", base64.StdEncoding.EncodeToString(bundleJSON),
		"__CA__", base64.StdEncoding.EncodeToString(s.ps.MITMCAPEM()),
		"__BASE__", scheme+"://"+r.Host,
	).Replace(setupScript)

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="poxy-setup-%s.ps1"`, name))
	w.Write([]byte(script))
}

// handleDownloadClient serve il binario poxy-client.exe se presente sul server.
func (s *Server) handleDownloadClient(w http.ResponseWriter, r *http.Request) {
	p := clientBinaryPath()
	if p == "" {
		http.Error(w, "binario client non disponibile sul server (metti poxy-client.exe accanto a poxy-server.exe)", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="poxy-client.exe"`)
	http.ServeFile(w, r, p)
}

func clientBinaryPath() string {
	var candidates []string
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "poxy-client.exe"))
	}
	candidates = append(candidates, "poxy-client.exe")
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c
		}
	}
	return ""
}

const setupScript = `# poxy - installer locale (Windows). Esegui come Amministratore.
$ErrorActionPreference = "Stop"
Write-Host "Installazione poxy client..."

$dir = "$env:LOCALAPPDATA\poxy"
New-Item -ItemType Directory -Force -Path $dir | Out-Null

# bundle + CA incorporati
[IO.File]::WriteAllBytes("$dir\bundle.json", [Convert]::FromBase64String("__BUNDLE__"))
[IO.File]::WriteAllBytes("$dir\mitm-ca.crt", [Convert]::FromBase64String("__CA__"))

# scarica il client
Write-Host "Scarico poxy-client..."
Invoke-WebRequest -Uri "__BASE__/download/poxy-client.exe" -OutFile "$dir\poxy-client.exe"

# fidati della MITM CA (store Root di Windows)
Write-Host "Installo la MITM CA nello store Root..."
certutil -addstore -f Root "$dir\mitm-ca.crt" | Out-Null

# variabili per Node / Claude Code / CLI
setx NODE_EXTRA_CA_CERTS "$dir\mitm-ca.crt" | Out-Null
setx HTTPS_PROXY "http://127.0.0.1:8888" | Out-Null
setx HTTP_PROXY  "http://127.0.0.1:8888" | Out-Null
setx NO_PROXY "localhost,127.0.0.1" | Out-Null

# proxy di sistema (browser / Claude Desktop / Electron)
$reg = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
Set-ItemProperty $reg -Name ProxyEnable -Value 1
Set-ItemProperty $reg -Name ProxyServer -Value "127.0.0.1:8888"
Set-ItemProperty $reg -Name ProxyOverride -Value "localhost;127.0.0.1;<local>"

# avvio automatico al login (VBS nascosto)
$exe = "$dir\poxy-client.exe"
$bundle = "$dir\bundle.json"
$startup = [Environment]::GetFolderPath('Startup')
$vbs = "$startup\poxy-client.vbs"
$vbsLine = 'CreateObject("WScript.Shell").Run """' + $exe + '"" -bundle ""' + $bundle + '"" -listen 127.0.0.1:8888", 0, False'
Set-Content -Encoding ASCII -LiteralPath $vbs -Value $vbsLine

# avvia ora
Start-Process -FilePath $exe -ArgumentList '-bundle', $bundle, '-listen', '127.0.0.1:8888' -WindowStyle Hidden

Write-Host ""
Write-Host "poxy installato in $dir"
Write-Host "Proxy attivo su 127.0.0.1:8888 - avvio automatico configurato."
Write-Host "Riapri terminali e app per applicare le variabili d'ambiente."
`

// --- Helper ---

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func newToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}
