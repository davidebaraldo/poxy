// Package traffic raccoglie gli eventi di traffico proxato e li distribuisce ai
// sottoscrittori (interfaccia web) oltre a mantenerne un buffer circolare.
package traffic

import (
	"sync"
	"sync/atomic"
	"time"
)

// Entry descrive una singola richiesta proxata.
type Entry struct {
	ID          int64     `json:"id"`
	Time        time.Time `json:"time"`
	ClientID    string    `json:"clientId"`
	ClientAddr  string    `json:"clientAddr"`
	Scheme      string    `json:"scheme"`
	Method      string    `json:"method"`
	Host        string    `json:"host"`
	Path        string    `json:"path"`
	Status      int       `json:"status"`
	ReqBytes    int64     `json:"reqBytes"`
	RespBytes   int64     `json:"respBytes"`
	DurationMs  int64     `json:"durationMs"`
	Blocked     bool      `json:"blocked"`
	MatchedRule string    `json:"matchedRule"`
	Fingerprint string    `json:"fingerprint"`
	UserAgent   string    `json:"userAgent"`
	Error       string    `json:"error"`

	ReqHeaders  map[string][]string `json:"reqHeaders,omitempty"`
	RespHeaders map[string][]string `json:"respHeaders,omitempty"`

	ReqBody           string `json:"reqBody,omitempty"`  // base64, cap 32KB
	RespBody          string `json:"respBody,omitempty"` // base64, cap 32KB
	ReqBodyTruncated  bool   `json:"reqBodyTruncated,omitempty"`
	RespBodyTruncated bool   `json:"respBodyTruncated,omitempty"`
}

// Stats sono i totali aggregati mostrati in dashboard.
type Stats struct {
	Total     int64 `json:"total"`
	Blocked   int64 `json:"blocked"`
	Errors    int64 `json:"errors"`
	BytesIn   int64 `json:"bytesIn"`
	BytesOut  int64 `json:"bytesOut"`
	Connected int   `json:"connected"`
}

// Hub è il bus centrale degli eventi di traffico.
type Hub struct {
	seq     atomic.Int64
	mu      sync.RWMutex
	ring    []Entry
	ringCap int
	next    int
	full    bool
	subs    map[int]chan Entry
	subSeq  int

	total, blocked, errs   atomic.Int64
	bytesIn, bytesOut      atomic.Int64
}

// NewHub crea un hub con un buffer circolare di capacità ringCap.
func NewHub(ringCap int) *Hub {
	if ringCap <= 0 {
		ringCap = 2000
	}
	return &Hub{
		ring:    make([]Entry, ringCap),
		ringCap: ringCap,
		subs:    make(map[int]chan Entry),
	}
}

// NextID assegna un identificatore progressivo a un evento in corso.
func (h *Hub) NextID() int64 { return h.seq.Add(1) }

// Publish registra un evento completato e lo inoltra ai sottoscrittori.
func (h *Hub) Publish(e Entry) {
	h.total.Add(1)
	if e.Blocked {
		h.blocked.Add(1)
	}
	if e.Error != "" {
		h.errs.Add(1)
	}
	h.bytesOut.Add(e.ReqBytes)
	h.bytesIn.Add(e.RespBytes)

	h.mu.Lock()
	h.ring[h.next] = e
	h.next = (h.next + 1) % h.ringCap
	if h.next == 0 {
		h.full = true
	}
	subs := make([]chan Entry, 0, len(h.subs))
	for _, ch := range h.subs {
		subs = append(subs, ch)
	}
	h.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- e:
		default: // sottoscrittore lento: si salta l'evento live (resta nel ring)
		}
	}
}

// Recent restituisce fino a limit eventi recenti, dal più vecchio al più nuovo.
func (h *Hub) Recent(limit int) []Entry {
	h.mu.RLock()
	defer h.mu.RUnlock()
	var all []Entry
	if h.full {
		all = append(all, h.ring[h.next:]...)
		all = append(all, h.ring[:h.next]...)
	} else {
		all = append(all, h.ring[:h.next]...)
	}
	if limit > 0 && len(all) > limit {
		all = all[len(all)-limit:]
	}
	return all
}

// Subscribe registra un canale che riceverà gli eventi futuri. La funzione di
// ritorno annulla la sottoscrizione.
func (h *Hub) Subscribe() (<-chan Entry, func()) {
	ch := make(chan Entry, 256)
	h.mu.Lock()
	id := h.subSeq
	h.subSeq++
	h.subs[id] = ch
	h.mu.Unlock()
	return ch, func() {
		// Non si chiude il canale: Publish potrebbe ancora tenerne un
		// riferimento fuori dal lock e un send su canale chiuso causerebbe
		// panic. Basta rimuoverlo dalla mappa; il GC lo raccoglie.
		h.mu.Lock()
		delete(h.subs, id)
		h.mu.Unlock()
	}
}

// Snapshot restituisce i totali correnti; connected va passato dall'esterno.
func (h *Hub) Snapshot(connected int) Stats {
	return Stats{
		Total:     h.total.Load(),
		Blocked:   h.blocked.Load(),
		Errors:    h.errs.Load(),
		BytesIn:   h.bytesIn.Load(),
		BytesOut:  h.bytesOut.Load(),
		Connected: connected,
	}
}
