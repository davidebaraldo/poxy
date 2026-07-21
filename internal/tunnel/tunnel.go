// Package tunnel definisce il protocollo condiviso tra poxy-client e
// poxy-server: il preambolo di stream e il bundle di provisioning del client.
package tunnel

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/hashicorp/yamux"
)

// YamuxConfig è la configurazione condivisa del multiplexer. Alza la finestra
// di stream a 4MB (default 256KB) per non strozzare il throughput sui link a
// latenza alta (client remoti/WAN).
func YamuxConfig() *yamux.Config {
	c := yamux.DefaultConfig()
	c.MaxStreamWindowSize = 4 * 1024 * 1024
	c.KeepAliveInterval = 15 * time.Second
	c.ConnectionWriteTimeout = 30 * time.Second
	return c
}

// Modalità di uno stream aperto dal client verso il server.
const (
	ModeTLS  = "tls"  // il client sta tunnelando un handshake TLS da intercettare
	ModeHTTP = "http" // il client sta inoltrando una singola richiesta HTTP in chiaro
	ModeCtl  = "ctl"  // canale di controllo (es. "ctl routes" -> lista domini proxati)
)

// ServerName è il ServerName atteso dal client nell'mTLS del tunnel. Il
// certificato server del tunnel viene emesso con questo SAN, così il client non
// dipende dall'hostname/IP reale del server.
const ServerName = "poxy-tunnel"

// WritePreamble scrive la riga di preambolo "<mode> <target>\n".
func WritePreamble(w io.Writer, mode, target string) error {
	_, err := fmt.Fprintf(w, "%s %s\n", mode, target)
	return err
}

// ReadPreamble legge e valida la riga di preambolo.
func ReadPreamble(r *bufio.Reader) (mode, target string, err error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", "", err
	}
	line = strings.TrimRight(line, "\r\n")
	parts := strings.SplitN(line, " ", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("tunnel: preambolo malformato %q", line)
	}
	mode, target = parts[0], parts[1]
	if mode != ModeTLS && mode != ModeHTTP && mode != ModeCtl {
		return "", "", fmt.Errorf("tunnel: modalità sconosciuta %q", mode)
	}
	return mode, target, nil
}

// Bundle è il pacchetto di provisioning consegnato a una macchina client:
// contiene tutto il necessario per stabilire il tunnel mTLS e per fidarsi della
// MITM CA.
type Bundle struct {
	ServerAddr    string `json:"serverAddr"`    // host:port del listener tunnel
	Name          string `json:"name"`          // identificativo del client
	TunnelCAPEM   string `json:"tunnelCaPem"`   // CA che valida il certificato server del tunnel
	ClientCertPEM string `json:"clientCertPem"` // certificato client (mTLS)
	ClientKeyPEM  string `json:"clientKeyPem"`  // chiave privata client
	MITMCAPEM     string `json:"mitmCaPem"`     // CA MITM da installare come trusted root
}
