// poxy.pac — instrada verso poxy SOLO i domini elencati; tutto il resto DIRECT.
// Windows: Impostazioni > Rete e Internet > Proxy > "Usa script di
//   installazione" > Indirizzo: file:///C:/Users/Davide/Desktop/poxy/examples/poxy.pac
// (vale per browser/app che rispettano il proxy di sistema; NON per Node/Claude Code)
function FindProxyForURL(url, host) {
  var proxied = [
    "anthropic.com",
    "claude.ai",
    "claude.com",
    "claudeusercontent.com",
    "storage.googleapis.com",
    "raw.githubusercontent.com",
    "datadoghq.com",
    "browser-intake-us5-datadoghq.com",
    "brew.sh",
    "npmjs.org",
    "npmjs.com",
    "sentry.io",
    "statsig.com",
    "statsigapi.net"
  ];
  for (var i = 0; i < proxied.length; i++) {
    var d = proxied[i];
    if (host === d || dnsDomainIs(host, "." + d)) {
      return "PROXY 127.0.0.1:8888";
    }
  }
  return "DIRECT";
}
