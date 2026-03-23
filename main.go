package main

import (
  "context"
  "errors"
  "fmt"
  "io"
  "log"
  "net"
  "net/http"
  "net/netip"
  "net/url"
  "os"
  "slices"
  "strings"
  "time"
)

const (
  listenAddr      = ":8080"
  maxRequestBody  = 10 << 20 // 10 MiB
  upstreamTimeout = 30 * time.Second
)

var hopByHopHeaders = []string{
  "Connection",
  "Proxy-Connection",
  "Keep-Alive",
  "Proxy-Authenticate",
  "Proxy-Authorization",
  "Te",
  "Trailer",
  "Transfer-Encoding",
  "Upgrade",
}

func main() {
  logger := log.New(os.Stdout, "[proxy] ", log.LstdFlags|log.Lmicroseconds)

  resolver := &net.Resolver{}

  transport := &http.Transport{
    Proxy: nil,
    DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
      host, port, err := net.SplitHostPort(address)
      if err != nil {
        return nil, fmt.Errorf("split host/port: %w", err)
      }

      ips, err := resolver.LookupNetIP(ctx, "ip", host)
      if err != nil {
        return nil, fmt.Errorf("dns lookup failed for %q: %w", host, err)
      }
      if len(ips) == 0 {
        return nil, fmt.Errorf("no IPs for host %q", host)
      }

      dialer := &net.Dialer{
        Timeout:   10 * time.Second,
        KeepAlive: 30 * time.Second,
      }

      var errs []string
      for _, ip := range ips {
        if blockedNetip(ip) {
          errs = append(errs, fmt.Sprintf("%s blocked", ip.String()))
          continue
        }

        conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
        if err == nil {
          return conn, nil
        }
        errs = append(errs, fmt.Sprintf("%s: %v", ip.String(), err))
      }

      return nil, fmt.Errorf("all resolved IPs rejected/failed for %q: %s", host, strings.Join(errs, "; "))
    },
    ForceAttemptHTTP2:     true,
    MaxIdleConns:          100,
    MaxIdleConnsPerHost:   10,
    IdleConnTimeout:       90 * time.Second,
    TLSHandshakeTimeout:   10 * time.Second,
    ResponseHeaderTimeout: 20 * time.Second,
    ExpectContinueTimeout: 1 * time.Second,
  }

  client := &http.Client{
    Transport: transport,
    Timeout:   upstreamTimeout,
    CheckRedirect: func(req *http.Request, via []*http.Request) error {
      if len(via) >= 5 {
        return errors.New("too many redirects")
      }
      return validateTargetURL(req.URL)
    },
  }

  mux := http.NewServeMux()
  mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    start := time.Now()

    if r.Method != http.MethodGet &&
      r.Method != http.MethodPost &&
      r.Method != http.MethodPut &&
      r.Method != http.MethodPatch &&
      r.Method != http.MethodDelete &&
      r.Method != http.MethodHead {
      http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
      return
    }

    r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

    targetRaw := strings.TrimSpace(r.URL.Query().Get("url"))
    if targetRaw == "" {
      targetRaw = strings.TrimSpace(r.Header.Get("X-Target-URL"))
    }
    if targetRaw == "" {
      http.Error(w, "missing target url", http.StatusBadRequest)
      return
    }

    targetURL, err := url.Parse(targetRaw)
    if err != nil {
      http.Error(w, "invalid target url", http.StatusBadRequest)
      return
    }
    if err := validateTargetURL(targetURL); err != nil {
      http.Error(w, "blocked target: "+err.Error(), http.StatusForbidden)
      return
    }

    var body io.Reader
    if r.Body != nil {
      body = r.Body
    }

    upReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL.String(), body)
    if err != nil {
      http.Error(w, "failed to build upstream request", http.StatusBadGateway)
      return
    }

    copyRequestHeaders(upReq.Header, r.Header)
    removeHopByHop(upReq.Header)

    upReq.Host = targetURL.Host
    upReq.Header.Set("Host", targetURL.Host)
    appendForwardedFor(upReq.Header, r.RemoteAddr)

    resp, err := client.Do(upReq)
    if err != nil {
      logger.Printf("upstream error method=%s target=%q err=%v dur=%s", r.Method, targetURL.String(), err, time.Since(start))
      http.Error(w, "upstream request failed", http.StatusBadGateway)
      return
    }
    defer resp.Body.Close()

    removeHopByHop(resp.Header)
    copyResponseHeaders(w.Header(), resp.Header)
    w.WriteHeader(resp.StatusCode)

    if _, err := io.Copy(w, resp.Body); err != nil {
      logger.Printf("response copy error method=%s target=%q err=%v dur=%s", r.Method, targetURL.String(), err, time.Since(start))
      return
    }

    logger.Printf("ok method=%s target=%q status=%d dur=%s", r.Method, targetURL.String(), resp.StatusCode, time.Since(start))
  })

  srv := &http.Server{
    Addr:              listenAddr,
    Handler:           loggingMiddleware(logger, mux),
    ReadHeaderTimeout: 5 * time.Second,
  }

  logger.Printf("listening on %s", listenAddr)
  log.Fatal(srv.ListenAndServe())
}

func validateTargetURL(u *url.URL) error {
  if u == nil {
    return errors.New("empty url")
  }

  if u.Scheme != "http" && u.Scheme != "https" {
    return errors.New("only http/https allowed")
  }

  if u.User != nil {
    return errors.New("userinfo not allowed")
  }

  host := u.Hostname()
  if host == "" {
    return errors.New("missing host")
  }

  if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
    return errors.New("localhost is blocked")
  }

  if ip, err := netip.ParseAddr(host); err == nil {
    if blockedNetip(ip) {
      return fmt.Errorf("ip %s is blocked", ip.String())
    }
  }

  return nil
}

func blockedIP(ip net.IP) bool {
  addr, ok := netip.AddrFromSlice(ip)
  if !ok {
    return true
  }
  return blockedNetip(addr)
}

func blockedNetip(ip netip.Addr) bool {
  if !ip.IsValid() {
    return true
  }

  if ip.IsLoopback() ||
    ip.IsPrivate() ||
    ip.IsMulticast() ||
    ip.IsLinkLocalUnicast() ||
    ip.IsLinkLocalMulticast() ||
    ip.IsUnspecified() {
    return true
  }

  blockedCIDRs := []string{
    "100.64.0.0/10",   // CGNAT
    "192.0.0.0/24",
    "192.0.2.0/24",    // TEST-NET-1
    "198.18.0.0/15",   // benchmarking
    "198.51.100.0/24", // TEST-NET-2
    "203.0.113.0/24",  // TEST-NET-3
    "224.0.0.0/4",     // multicast/reserved
    "240.0.0.0/4",     // reserved
    "::1/128",
    "fc00::/7",        // ULA
    "fe80::/10",       // link-local
    "ff00::/8",        // multicast
    "2001:db8::/32",   // docs
  }

  for _, cidr := range blockedCIDRs {
    prefix := netip.MustParsePrefix(cidr)
    if prefix.Contains(ip) {
      return true
    }
  }

  return false
}

func copyRequestHeaders(dst, src http.Header) {
  for k, vv := range src {
    if strings.EqualFold(k, "Host") {
      continue
    }
    for _, v := range vv {
      dst.Add(k, v)
    }
  }
}

func copyResponseHeaders(dst, src http.Header) {
  for k, vv := range src {
    for _, v := range vv {
      dst.Add(k, v)
    }
  }
}

func removeHopByHop(h http.Header) {
  for _, k := range hopByHopHeaders {
    h.Del(k)
  }

  for _, v := range h.Values("Connection") {
    for _, token := range strings.Split(v, ",") {
      token = strings.TrimSpace(token)
      if token != "" {
        h.Del(token)
      }
    }
  }
}

func appendForwardedFor(h http.Header, remoteAddr string) {
  host, _, err := net.SplitHostPort(remoteAddr)
  if err != nil {
    host = remoteAddr
  }

  existing := h.Values("X-Forwarded-For")
  if len(existing) == 0 {
    h.Set("X-Forwarded-For", host)
    return
  }

  parts := []string{strings.Join(existing, ", "), host}
  h.Set("X-Forwarded-For", strings.Join(parts, ", "))
}

func loggingMiddleware(logger *log.Logger, next http.Handler) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    if slices.Contains([]string{"CONNECT", "TRACE", "OPTIONS"}, r.Method) {
      http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
      return
    }
    next.ServeHTTP(w, r)
  })
}
