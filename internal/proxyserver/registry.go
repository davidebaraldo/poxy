package proxyserver

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// ClientEntry rappresenta un client connesso al tunnel.
type ClientEntry struct {
	ID    string
	Addr  string
	Since time.Time

	streams atomic.Int64
	reqs    atomic.Int64
}

// ClientInfo è la vista serializzabile di un client connesso.
type ClientInfo struct {
	ID       string    `json:"id"`
	Addr     string    `json:"addr"`
	Since    time.Time `json:"since"`
	Streams  int64     `json:"streams"`
	Requests int64     `json:"requests"`
}

// Registry tiene traccia dei client attualmente connessi.
type Registry struct {
	mu sync.Mutex
	m  map[*ClientEntry]struct{}
}

// NewRegistry crea un registry vuoto.
func NewRegistry() *Registry {
	return &Registry{m: make(map[*ClientEntry]struct{})}
}

// Add registra un nuovo client connesso.
func (r *Registry) Add(id, addr string) *ClientEntry {
	e := &ClientEntry{ID: id, Addr: addr, Since: time.Now()}
	r.mu.Lock()
	r.m[e] = struct{}{}
	r.mu.Unlock()
	return e
}

// Remove deregistra un client.
func (r *Registry) Remove(e *ClientEntry) {
	r.mu.Lock()
	delete(r.m, e)
	r.mu.Unlock()
}

// Count restituisce il numero di client connessi.
func (r *Registry) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.m)
}

// List restituisce lo snapshot ordinato dei client connessi.
func (r *Registry) List() []ClientInfo {
	r.mu.Lock()
	out := make([]ClientInfo, 0, len(r.m))
	for e := range r.m {
		out = append(out, ClientInfo{
			ID:       e.ID,
			Addr:     e.Addr,
			Since:    e.Since,
			Streams:  e.streams.Load(),
			Requests: e.reqs.Load(),
		})
	}
	r.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Since.Before(out[j].Since) })
	return out
}
