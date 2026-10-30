// rux-tsnet is the built-in Tailscale device for rux-server.
//
// It speaks newline-delimited JSON on stdin/stdout and proxies HTTPS on
// https://<hostname>.<tailnet>.ts.net to the server. The auth key is read
// from the enable request and is never written to the log.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"tailscale.com/client/tailscale"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"
)

func main() {
	stateDir := flag.String("state-dir", "", "directory for the tsnet node state")
	backend := flag.String("backend", "", "unix:///path or http://host:port of rux-server")
	token := flag.String("token", "", "shared secret stamped on proxied requests")
	flag.Parse()
	if *stateDir == "" || *backend == "" || *token == "" {
		log.Fatal("rux-tsnet requires --state-dir, --backend, and --token")
	}
	app := &sidecar{
		stateDir: *stateDir,
		backend:  *backend,
		token:    *token,
		phase:    "disabled",
		hostname: "rex",
	}
	dec := json.NewDecoder(os.Stdin)
	for {
		var req map[string]any
		if err := dec.Decode(&req); err != nil {
			if err == io.EOF {
				return
			}
			app.fail(0, err.Error())
			return
		}
		id, _ := req["id"].(float64)
		op, _ := req["op"].(string)
		status, err := app.handle(op, req)
		if err != nil {
			app.write(map[string]any{"id": id, "ok": false, "message": err.Error()})
			continue
		}
		app.write(map[string]any{"id": id, "ok": true, "status": status})
	}
}

type sidecar struct {
	mu           sync.Mutex
	outMu        sync.Mutex
	stateDir     string
	backend      string
	token        string
	hostname     string
	allowMembers bool
	tags         []string
	phase        string
	authURL      string
	loginStarted bool
	httpsState   string
	errorText    string
	dnsName      string
	account      string
	tailnetName  string
	ownerUser    string
	srv          *tsnet.Server
	https        net.Listener
	cancelWatch  context.CancelFunc
}

func (s *sidecar) handle(op string, req map[string]any) (map[string]any, error) {
	switch op {
	case "enable":
		return s.enable(req)
	case "set_members":
		s.mu.Lock()
		if value, ok := req["allow_tailnet_members"].(bool); ok {
			s.allowMembers = value
		}
		status := s.statusLocked()
		s.mu.Unlock()
		return status, nil
	case "disable":
		return s.stop(false)
	case "logout":
		return s.logout()
	case "login":
		return s.login()
	case "rename":
		name, _ := req["hostname"].(string)
		return s.rename(name)
	case "status":
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.statusLocked(), nil
	default:
		return nil, fmt.Errorf("unknown op %s", op)
	}
}

func (s *sidecar) enable(req map[string]any) (map[string]any, error) {
	s.mu.Lock()
	if s.srv != nil {
		if value, ok := req["allow_tailnet_members"].(bool); ok {
			s.allowMembers = value
		}
		status := s.statusLocked()
		s.mu.Unlock()
		return status, nil
	}
	if name, ok := req["hostname"].(string); ok && name != "" {
		s.hostname = name
	}
	if value, ok := req["allow_tailnet_members"].(bool); ok {
		s.allowMembers = value
	}
	s.tags = stringList(req["advertise_tags"])
	hostname := s.hostname
	tags := append([]string(nil), s.tags...)
	s.mu.Unlock()

	authKey, _ := req["auth_key"].(string)
	req["auth_key"] = ""
	srv := &tsnet.Server{
		Dir:      s.stateDir,
		Hostname: hostname,
		AuthKey:  authKey,
		UserLogf: func(format string, args ...any) {
			msg := fmt.Sprintf(format, args...)
			if found := firstURL(msg); found != "" {
				s.mu.Lock()
				s.authURL = found
				s.mu.Unlock()
			}
			log.Print(msg)
		},
		Logf: func(string, ...any) {},
	}
	authKey = ""
	if err := srv.Start(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.srv = srv
	s.phase = "starting"
	s.httpsState = "pending"
	s.errorText = ""
	ctx, cancel := context.WithCancel(context.Background())
	s.cancelWatch = cancel
	status := s.statusLocked()
	s.mu.Unlock()
	go s.watch(ctx)
	if len(tags) > 0 {
		go s.advertise(tags)
	}
	return status, nil
}

func (s *sidecar) advertise(tags []string) {
	lc, err := s.client()
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	prefs := ipn.NewPrefs()
	prefs.AdvertiseTags = tags
	prefs.WantRunning = true
	_, err = lc.EditPrefs(ctx, &ipn.MaskedPrefs{
		Prefs:            *prefs,
		AdvertiseTagsSet: true,
		WantRunningSet:   true,
	})
	if err != nil {
		log.Printf("advertise tags: %v", err)
	}
}

func (s *sidecar) login() (map[string]any, error) {
	s.mu.Lock()
	if s.srv == nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("built-in Tailscale is off")
	}
	if s.loginStarted {
		status := s.statusLocked()
		s.mu.Unlock()
		return status, nil
	}
	s.loginStarted = true
	s.mu.Unlock()
	lc, err := s.client()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := lc.StartLoginInteractive(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase != "running" {
		s.phase = "needs_login"
	}
	return s.statusLocked(), nil
}

func (s *sidecar) logout() (map[string]any, error) {
	s.mu.Lock()
	srv := s.srv
	s.mu.Unlock()
	if srv == nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.statusLocked(), nil
	}
	lc, err := srv.LocalClient()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := lc.Logout(ctx); err != nil {
		return nil, err
	}
	return s.stop(true)
}

func (s *sidecar) rename(hostname string) (map[string]any, error) {
	s.mu.Lock()
	srv := s.srv
	if srv == nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("built-in Tailscale is off")
	}
	s.hostname = hostname
	s.mu.Unlock()
	lc, err := srv.LocalClient()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	prefs := ipn.NewPrefs()
	prefs.Hostname = hostname
	if _, err := lc.EditPrefs(ctx, &ipn.MaskedPrefs{Prefs: *prefs, HostnameSet: true}); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.statusLocked(), nil
}

func (s *sidecar) stop(signedOut bool) (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancelWatch != nil {
		s.cancelWatch()
		s.cancelWatch = nil
	}
	if s.https != nil {
		_ = s.https.Close()
		s.https = nil
	}
	if s.srv != nil {
		_ = s.srv.Close()
		s.srv = nil
	}
	s.phase = "disabled"
	s.httpsState = ""
	s.authURL = ""
	s.loginStarted = false
	if signedOut {
		s.tags = nil
	}
	return s.statusLocked(), nil
}

func (s *sidecar) watch(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.poll()
		}
	}
}

func (s *sidecar) poll() {
	lc, err := s.client()
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := lc.Status(ctx)
	if err != nil || st == nil {
		return
	}
	s.mu.Lock()
	s.applyStatus(st)
	if s.phase == "running" && s.https == nil && s.httpsState != "failed" {
		s.mu.Unlock()
		s.serveHTTPS()
		return
	}
	status := s.statusLocked()
	s.mu.Unlock()
	s.emit(status)
}

func (s *sidecar) serveHTTPS() {
	s.mu.Lock()
	srv := s.srv
	s.mu.Unlock()
	if srv == nil {
		return
	}
	ln, err := srv.ListenTLS("tcp", ":443")
	if err != nil {
		s.mu.Lock()
		s.phase = "disabled"
		s.httpsState = ""
		s.errorText = "https listener failed: " + err.Error()
		if s.srv != nil {
			_ = s.srv.Close()
			s.srv = nil
		}
		status := s.statusLocked()
		s.mu.Unlock()
		s.emit(status)
		return
	}
	s.mu.Lock()
	s.https = ln
	s.httpsState = "available"
	status := s.statusLocked()
	s.mu.Unlock()
	s.emit(status)
	proxy := s.proxy()
	_ = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authorize(r) {
			http.Error(w, "tailnet peer is not authorized", http.StatusForbidden)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
}

func (s *sidecar) authorize(r *http.Request) bool {
	lc, err := s.client()
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	who, err := lc.WhoIs(ctx, r.RemoteAddr)
	if err != nil || who == nil || who.Node == nil {
		return false
	}
	peerUser := ""
	login := ""
	if who.UserProfile != nil {
		peerUser = who.UserProfile.ID.String()
		login = who.UserProfile.LoginName
	}
	var tags []string
	if who.Node.Tags != nil {
		tags = who.Node.Tags
	}
	nodeName := who.Node.ComputedName
	s.mu.Lock()
	owner := s.ownerUser
	allow := s.allowMembers
	token := s.token
	s.mu.Unlock()
	if !admitPeer(owner, peerUser, len(tags) > 0, allow) {
		return false
	}
	r.Header.Set("X-Rux-Tsnet-Token", token)
	r.Header.Set("X-Rux-Tsnet-User", peerUser)
	r.Header.Set("X-Rux-Tsnet-Login", login)
	r.Header.Set("X-Rux-Tsnet-Node", nodeName)
	r.Header.Set("X-Rux-Tsnet-Tags", strings.Join(tags, ","))
	r.Header.Set("X-Rux-Tsnet-Remote", r.RemoteAddr)
	return true
}

func (s *sidecar) proxy() *httputil.ReverseProxy {
	transport := http.DefaultTransport
	target := s.backend
	if strings.HasPrefix(target, "unix://") {
		path := strings.TrimPrefix(target, "unix://")
		transport = &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", path)
			},
		}
		target = "http://rux"
	}
	parsed, err := url.Parse(target)
	if err != nil {
		parsed, _ = url.Parse("http://rux")
	}
	return &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(req *httputil.ProxyRequest) {
			req.SetURL(parsed)
		},
	}
}

func (s *sidecar) applyStatus(st *ipnstate.Status) {
	if st.AuthURL != "" {
		s.authURL = st.AuthURL
	}
	switch st.BackendState {
	case "Running":
		s.phase = "running"
		s.loginStarted = false
	case "NeedsLogin":
		s.phase = "needs_login"
	case "NeedsMachineAuth":
		s.phase = "needs_machine_approval"
	case "Stopped":
		s.phase = "disabled"
	default:
		if s.phase != "running" {
			s.phase = "starting"
		}
	}
	if st.Self != nil {
		name := strings.TrimSuffix(st.Self.DNSName, ".")
		if name != "" {
			s.dnsName = name
		}
		if st.Self.Tags != nil && st.Self.Tags.Len() > 0 {
			s.tags = nil
			for i := 0; i < st.Self.Tags.Len(); i++ {
				s.tags = append(s.tags, st.Self.Tags.At(i))
			}
		}
		if st.User != nil {
			if user, ok := st.User[st.Self.UserID]; ok {
				s.account = user.LoginName
				s.ownerUser = user.ID.String()
			}
		}
	}
	if st.CurrentTailnet != nil && st.CurrentTailnet.Name != "" {
		s.tailnetName = st.CurrentTailnet.Name
	} else if st.MagicDNSSuffix != "" {
		s.tailnetName = st.MagicDNSSuffix
	}
}

func (s *sidecar) statusLocked() map[string]any {
	status := map[string]any{
		"state":                 s.phase,
		"allow_tailnet_members": s.allowMembers,
	}
	if s.errorText != "" {
		status["error"] = s.errorText
	}
	if s.dnsName != "" {
		status["dns_name"] = s.dnsName
	}
	if s.phase == "needs_login" && s.authURL != "" {
		status["auth_url"] = s.authURL
	}
	if s.account != "" {
		status["account"] = map[string]any{"login_name": s.account}
	}
	if s.tailnetName != "" {
		status["tailnet_name"] = s.tailnetName
	}
	if len(s.tags) > 0 {
		status["tags"] = s.tags
	}
	if s.httpsState != "" && s.phase != "disabled" {
		https := map[string]any{"state": s.httpsState}
		if s.httpsState == "available" && s.dnsName != "" {
			https["url"] = "https://" + s.dnsName
		}
		status["https"] = https
	}
	return status
}

func (s *sidecar) client() (*tailscale.LocalClient, error) {
	s.mu.Lock()
	srv := s.srv
	s.mu.Unlock()
	if srv == nil {
		return nil, fmt.Errorf("built-in Tailscale is off")
	}
	return srv.LocalClient()
}

func (s *sidecar) emit(status map[string]any) {
	s.write(map[string]any{"event": "status", "status": status})
}

func (s *sidecar) fail(id float64, message string) {
	s.write(map[string]any{"id": id, "ok": false, "message": message})
}

func (s *sidecar) write(value map[string]any) {
	s.outMu.Lock()
	defer s.outMu.Unlock()
	_ = json.NewEncoder(os.Stdout).Encode(value)
}

func stringList(value any) []string {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, item := range items {
		if text, ok := item.(string); ok && text != "" {
			out = append(out, text)
		}
	}
	return out
}

func firstURL(text string) string {
	index := strings.Index(text, "https://")
	if index < 0 {
		return ""
	}
	rest := text[index:]
	if end := strings.IndexAny(rest, " \t\r\n"); end >= 0 {
		rest = rest[:end]
	}
	return strings.TrimRight(rest, ".,)")
}
