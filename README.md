# poxy

Egress proxy in Go. Le macchine client instradano tutto il traffico HTTP/HTTPS
verso un server centrale che esce con **un solo fingerprint TLS**, header/User-Agent
uniformati e IP unico. La destinazione vede solo il server, mai i client.

```
app ──> poxy-client (proxy locale) ──[ tunnel mTLS + yamux ]──> poxy-server
                                                                    │ MITM TLS (cert forgiati)
                                                                    │ strip/override header + User-Agent
                                                                    │ egress uTLS (fingerprint unico)
                                                                    ▼
                                                                destinazione
```

## Componenti

- **poxy-server** — accetta i tunnel, intercetta il TLS (MITM), riscrive gli
  header, esce con fingerprint uTLS unico. Serve il pannello web.
- **poxy-client** — proxy HTTP/HTTPS locale da installare sulle macchine.
  Multiplexa tutto su un unico tunnel mTLS.

## Come funziona l'intercettazione

Per rimuovere/riscrivere header *dentro* il TLS, il server termina la
connessione TLS presentando un certificato forgiato al volo, firmato dalla
**MITM CA**. Le macchine client devono fidarsi di questa CA (installala come
trusted root). Il server ristabilisce poi una **nuova** connessione TLS verso la
destinazione con il fingerprint scelto (uTLS): la destinazione vede solo il
ClientHello del server e il suo IP.

Due CA distinte:
- **Tunnel CA** — mTLS del tunnel client↔server (autenticazione dei client).
- **MITM CA** — firma i certificati foglia per l'intercettazione (va installata
  sui client come trusted root).

## Build

```
go build ./cmd/poxy-server
go build ./cmd/poxy-client
```

## Docker (server)

```
docker build -t poxy .
docker run -d --name poxy \
  -p 8080:8080 -p 9000:9000 \
  -v poxy-data:/data \
  ghcr.io/davidebaraldo/poxy:latest \
  -data /data -web 0.0.0.0:8080 -web-insecure -tunnel 0.0.0.0:9000 -public TUO_HOST:9000
docker logs poxy    # mostra la password del pannello al primo avvio
```

Il pannello web è in HTTP: tienilo dietro un reverse proxy TLS (o su rete fidata).
Il volume `/data` conserva le CA e la config — non perderlo o i client vanno riprovisionati.

## CI / release

`.github/workflows/build.yml`:
- test + `go vet` + build ad ogni push/PR;
- cross-compila **server e client** per Windows, macOS, Linux (amd64 + arm64);
- crea **archivi distribuibili** `poxy-server-<os>-<arch>.(zip|tar.gz)`: ognuno
  contiene il server + **tutti** i binari client + esempi + README, così il
  server serve gli installer per ogni piattaforma (`/download`, `/api/setup`);
- pubblica l'immagine server su GHCR (`ghcr.io/<owner>/poxy`);
- su tag `vX.Y.Z` allega archivi + `checksums.txt` a una GitHub Release.

Rilascio:
```
git tag v0.1.0 && git push origin v0.1.0
```
Poi scarichi `poxy-server-<tuo-os>-<arch>.*`, lo scompatti e avvii `poxy-server`:
serve pannello + installer per Windows/macOS/Linux, tutto incluso.

## Interfaccia

Pannello web multilingua (IT · EN · ES · FR · DE, auto-rilevata, selettore in
alto a destra), tema scuro, feed traffico in tempo reale con dettaglio per
richiesta (header e, se abilitato, body).

## Avvio server

```
poxy-server -data poxy-data -web 127.0.0.1:8080 -tunnel 0.0.0.0:9000 -public TUO_IP:9000
```

Al primo avvio genera le CA e stampa la password del pannello web. Apri
`http://127.0.0.1:8080`.

- `-public` deve essere l'host:port con cui i client raggiungono il tunnel:
  finisce nei bundle di provisioning.

## Provisioning di un client

1. Dal pannello (tab **client**) scarica la MITM CA e genera un **bundle**
   (`poxy-<nome>.json`) — contiene indirizzo server, certificato client mTLS e
   MITM CA.
2. Sulla macchina client, installa la MITM CA come trusted root:
   ```
   poxy-client -bundle poxy-nome.json -install-ca      # Windows (admin)
   ```
   Su Linux/macOS installa manualmente `mitm-ca.crt` nel trust store di sistema.
3. Avvia il proxy locale:
   ```
   poxy-client -bundle poxy-nome.json -listen 127.0.0.1:8080
   ```
4. Configura le app / il sistema per usare `127.0.0.1:8080` come proxy HTTP/HTTPS.

## Pannello web

- **dashboard** — statistiche + traffico in tempo reale (SSE).
- **domini** — regole per pattern (`example.com`, `*.example.com`, `*`): allow/block,
  header e User-Agent per-dominio.
- **uscita** — fingerprint TLS, User-Agent unico, header globali set/strip,
  azione di default (whitelist con `block`).
- **client** — client connessi, download CA e generazione bundle.
- **impostazioni** — cambio password.

## Sicurezza

- **Anti-SSRF**: l'uscita verso IP privati/loopback/link-local è bloccata per
  default (il controllo scatta dopo la risoluzione DNS, quindi neutralizza il
  DNS rebinding). Sbloccabile con la spunta *allowPrivate* nel tab uscita.
- **Pannello web**: solo loopback per default. Per un bind non-loopback serve
  TLS (`-web-cert`/`-web-key`) oppure il flag esplicito `-web-insecure`
  (sconsigliato: password e bundle — con chiave privata mTLS — in chiaro). Il
  cookie di sessione è `Secure` quando servito su HTTPS.
- **Login**: lockout progressivo dopo tentativi falliti; body delle API limitato.
- **Timeout**: ogni richiesta proxata ha un tetto complessivo per non lasciare
  goroutine/connessioni appese su upstream che stallano.

Limiti noti (non ancora implementati):
- Nessuna revoca dei certificati client del tunnel: per invalidare un client
  serve rigenerare la Tunnel CA (invalida tutti). Da valutare CRL/endpoint di revoca.
- Su Windows i permessi `0600` dei file CA non producono ACL restrittive: proteggi
  la data dir (contiene `mitm-ca.key`) con ACL a livello di filesystem.

## Note

- Il canale app→proxy locale è negoziato in HTTP/1.1 lato MITM; l'uscita verso
  la destinazione usa HTTP/1.1 o HTTP/2 secondo l'ALPN. gRPC/HTTP2 puro
  app→server non è supportato.
- Il proxy locale (`poxy-client`) non ha autenticazione: tienilo su loopback.
