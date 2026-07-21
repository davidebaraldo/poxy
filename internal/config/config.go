// Package config contiene lo schema di configurazione di poxy, la persistenza
// su file JSON e la risoluzione delle regole per host (dominio -> azione +
// header + user-agent effettivi).
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Action indica cosa fare con una richiesta verso un dominio.
const (
	ActionAllow = "allow"
	ActionBlock = "block"
)

// EgressConfig raccoglie le impostazioni globali applicate al traffico in
// uscita dal server.
type EgressConfig struct {
	// Fingerprint è la chiave del profilo TLS uTLS (vedi package egress).
	Fingerprint string `json:"fingerprint"`
	// UserAgent, se non vuoto, sovrascrive l'header User-Agent di ogni richiesta.
	UserAgent string `json:"userAgent"`
	// SetHeaders aggiunge/sovrascrive header su ogni richiesta.
	SetHeaders map[string]string `json:"setHeaders"`
	// StripHeaders elenca gli header (case-insensitive) da rimuovere.
	StripHeaders []string `json:"stripHeaders"`
	// DefaultAction è l'azione applicata ai domini senza regola esplicita.
	DefaultAction string `json:"defaultAction"`
	// AllowPrivate, se true, consente l'uscita verso IP privati/loopback/
	// link-local. Default false (bloccati, anti-SSRF).
	AllowPrivate bool `json:"allowPrivate"`
	// NormalizeFingerprint, se true, rimuove gli header che fingerprintano il
	// client (Client Hints, Sec-Fetch-*, Accept-Language, DNT, Priority, ...)
	// così tutti i client dietro poxy risultano indistinguibili tra loro.
	NormalizeFingerprint bool `json:"normalizeFingerprint"`
}

// DomainRule è una regola per un pattern di dominio. Campi vuoti ereditano dal
// globale.
type DomainRule struct {
	Pattern      string            `json:"pattern"`
	Action       string            `json:"action"`
	UserAgent    string            `json:"userAgent"`
	SetHeaders   map[string]string `json:"setHeaders"`
	StripHeaders []string          `json:"stripHeaders"`
	Note         string            `json:"note"`
}

// WebConfig contiene le impostazioni dell'interfaccia web.
type WebConfig struct {
	PasswordHash string `json:"passwordHash"`
}

// Config è l'intero stato configurabile di poxy.
type Config struct {
	Egress  EgressConfig `json:"egress"`
	Domains []DomainRule `json:"domains"`
	Web     WebConfig    `json:"web"`
}

// Effective è il risultato della risoluzione delle regole per un host.
type Effective struct {
	Action               string
	Fingerprint          string
	UserAgent            string
	SetHeaders           map[string]string
	StripHeaders         []string
	AllowPrivate         bool
	NormalizeFingerprint bool
	MatchedRule          string // pattern della regola dominio applicata, "" se solo globale
}

// Blocked indica se la richiesta va bloccata.
func (e Effective) Blocked() bool { return e.Action == ActionBlock }

// Default restituisce una configurazione iniziale sensata.
func Default() Config {
	return Config{
		Egress: EgressConfig{
			Fingerprint:   "chrome",
			UserAgent:     "",
			SetHeaders:    map[string]string{},
			StripHeaders:         []string{"X-Forwarded-For", "Forwarded", "Via", "X-Real-IP", "X-Client-IP"},
			DefaultAction:        ActionAllow,
			NormalizeFingerprint: true,
		},
		Domains: []DomainRule{},
		Web:     WebConfig{},
	}
}

// Store è un contenitore thread-safe della configurazione con persistenza.
type Store struct {
	path   string
	mu     sync.RWMutex
	cfg    Config
	saveMu sync.Mutex
}

// Load carica la configurazione dal path indicato, creandola con i valori di
// default se il file non esiste.
func Load(path string) (*Store, error) {
	s := &Store{path: path, cfg: Default()}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			if err := s.save(); err != nil {
				return nil, err
			}
			return s, nil
		}
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	normalize(&c)
	s.cfg = c
	return s, nil
}

func normalize(c *Config) {
	if c.Egress.SetHeaders == nil {
		c.Egress.SetHeaders = map[string]string{}
	}
	if c.Egress.DefaultAction == "" {
		c.Egress.DefaultAction = ActionAllow
	}
	if c.Egress.Fingerprint == "" {
		c.Egress.Fingerprint = "chrome"
	}
	for i := range c.Domains {
		if c.Domains[i].SetHeaders == nil {
			c.Domains[i].SetHeaders = map[string]string{}
		}
	}
}

// save marshalla la config corrente e la scrive. Va chiamata tenendo s.mu.
func (s *Store) save() error {
	data, err := json.MarshalIndent(s.cfg, "", "  ")
	if err != nil {
		return err
	}
	return s.writeFile(data)
}

// writeFile persiste i byte in modo atomico, serializzato da saveMu (separato da
// s.mu, così l'I/O su disco non blocca Resolve sull'hot path).
func (s *Store) writeFile(data []byte) error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Snapshot restituisce una copia della configurazione corrente.
func (s *Store) Snapshot() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneConfig(s.cfg)
}

// Update applica la mutazione fn alla configurazione e la persiste. La
// marshalizzazione avviene sotto s.mu, ma la scrittura su disco avviene fuori
// dal lock così Resolve() non resta bloccato durante l'I/O.
func (s *Store) Update(fn func(*Config)) error {
	s.mu.Lock()
	fn(&s.cfg)
	normalize(&s.cfg)
	data, err := json.MarshalIndent(s.cfg, "", "  ")
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return s.writeFile(data)
}

// Resolve calcola le impostazioni effettive per l'host indicato (senza porta).
func (s *Store) Resolve(host string) Effective {
	s.mu.RLock()
	defer s.mu.RUnlock()

	host = strings.ToLower(strings.TrimSuffix(host, "."))
	eff := Effective{
		Action:       s.cfg.Egress.DefaultAction,
		Fingerprint:  s.cfg.Egress.Fingerprint,
		UserAgent:    s.cfg.Egress.UserAgent,
		SetHeaders:           map[string]string{},
		StripHeaders:         append([]string{}, s.cfg.Egress.StripHeaders...),
		AllowPrivate:         s.cfg.Egress.AllowPrivate,
		NormalizeFingerprint: s.cfg.Egress.NormalizeFingerprint,
	}
	for k, v := range s.cfg.Egress.SetHeaders {
		eff.SetHeaders[k] = v
	}

	rule, ok := bestMatch(s.cfg.Domains, host)
	if !ok {
		return eff
	}
	eff.MatchedRule = rule.Pattern
	if rule.Action != "" {
		eff.Action = rule.Action
	}
	if rule.UserAgent != "" {
		eff.UserAgent = rule.UserAgent
	}
	for k, v := range rule.SetHeaders {
		eff.SetHeaders[k] = v
	}
	eff.StripHeaders = append(eff.StripHeaders, rule.StripHeaders...)
	return eff
}

// bestMatch sceglie la regola dominio più specifica che matcha l'host.
// Priorità: match esatto > wildcard più lunga > "*".
func bestMatch(rules []DomainRule, host string) (DomainRule, bool) {
	var best DomainRule
	bestScore := -1
	for _, r := range rules {
		score := matchScore(r.Pattern, host)
		if score > bestScore {
			bestScore = score
			best = r
		}
	}
	if bestScore < 0 {
		return DomainRule{}, false
	}
	return best, true
}

// matchScore restituisce un punteggio di specificità del match, oppure -1 se il
// pattern non matcha l'host.
func matchScore(pattern, host string) int {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if pattern == "" {
		return -1
	}
	if pattern == "*" {
		return 0
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		if strings.HasSuffix(host, suffix) && host != suffix[1:] {
			return len(pattern)
		}
		return -1
	}
	if pattern == host {
		return 1000 + len(pattern) // esatto: massima priorità
	}
	return -1
}

func cloneConfig(c Config) Config {
	out := c
	out.Egress.SetHeaders = map[string]string{}
	for k, v := range c.Egress.SetHeaders {
		out.Egress.SetHeaders[k] = v
	}
	out.Egress.StripHeaders = append([]string{}, c.Egress.StripHeaders...)
	out.Domains = make([]DomainRule, len(c.Domains))
	for i, d := range c.Domains {
		nd := d
		nd.SetHeaders = map[string]string{}
		for k, v := range d.SetHeaders {
			nd.SetHeaders[k] = v
		}
		nd.StripHeaders = append([]string{}, d.StripHeaders...)
		out.Domains[i] = nd
	}
	return out
}
