// gossipy.go
// Global gossip + DMs, QR share links, and a *mutual* handshake:
// - Always send PEER_REQ until we receive PEER_ACK from the peer.
// - /accept marks them accepted locally AND dials them to send PEER_ACK.
// - If we already accepted someone, incoming PEER_REQ triggers an auto PEER_ACK (no spam).
//
// Build: go build -o gossipy gossipy.go
// Run:   ./gossipy -iface tun0 -port 19999
//
// Commands:
//   /link                   show your gossipy:// link + QR
//   /accept <link|pub|id>   accept pending OR connect using a link (also sends PEER_ACK)
//   /pending                list pending peer requests
//   /contacts               list known contacts (nick, short, addr, accepted)
//   /peers                  list peer addresses
//   /unpeer <pub|id>        remove acceptance + drop stored peer addr
//   /nick <name>            set nickname
//   /msg <who> <text>       DM to nick|SHORTID|pubkey
//   /r <text>               reply to last *incoming* DM
//   /save                   save state
//   /quit                   exit
//
// Plain typing => global chat (Ygg transport-only encryption; app E2E can be added next).

package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	qrterminal "github.com/mdp/qrterminal/v3"
)

const version = "0.2.4"

// ---------- Config & State ----------

type Config struct {
	Nick       string          `json:"nick"`
	PrivKeyB64 string          `json:"privkey"`
	PubKeyB64  string          `json:"pubkey"`
	Peers      []string        `json:"peers"`     // [ipv6]:port
	ListenOn   string          `json:"listen_on"` // info
	Accepted   map[string]bool `json:"accepted"`  // pub -> we've accepted them
}

type Event struct {
	ID     string `json:"id"`
	Typ    string `json:"type"`   // "msg" or "dm"
	Author string `json:"author"` // base64 pub
	Nick   string `json:"nick"`
	Body   string `json:"body"`
	To     string `json:"to,omitempty"`
	TS     int64  `json:"ts"`
	Sig    string `json:"sig"`
}

type State struct {
	Events map[string]Event `json:"events"`
	Order  []string         `json:"order"`
}

// Wire messages
type WireMsg struct {
	Kind   string   `json:"kind"`           // "HELLO","HAVE","WANT","EVENT","PEER_REQ","PEER_ACK"
	Node   string   `json:"node,omitempty"` // base64 pub
	Nick   string   `json:"nick,omitempty"`
	Listen string   `json:"listen,omitempty"` // "[ipv6]:port"
	IDs    []string `json:"ids,omitempty"`
	Event  *Event   `json:"event,omitempty"`
}

// Contact info
type Contact struct {
	Pub       string
	Nick      string
	Addr      string
	LastSeen  time.Time
	Accepted  bool
	LastPrint time.Time // throttle request prints
}

// ---------- Node ----------

type Node struct {
	cfgPath string
	cfgMu   sync.Mutex
	cfg     *Config

	statePath string
	stateMu   sync.Mutex
	state     *State

	iface string
	yggIP net.IP
	port  int

	priv ed25519.PrivateKey
	pub  ed25519.PublicKey

	peersMu sync.Mutex
	peers   map[string]struct{} // addresses we dial

	contactsMu sync.Mutex
	contacts   map[string]*Contact // pub -> contact

	pendingMu sync.Mutex
	pending   map[string]*Contact // pub -> pending

	acceptedByMu sync.Mutex
	acceptedBy   map[string]bool // pub -> they have accepted US (session memo)

	lastDMFromMu sync.Mutex
	lastDMFrom   string

	quit chan struct{}
}

// ---------- Utils ----------

func saveJSONAtomic(path string, v any) error {
	tmp := path + ".tmp"
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func loadOrInitConfig(path string, nick string) (*Config, ed25519.PrivateKey, ed25519.PublicKey, error) {
	if _, err := os.Stat(path); err == nil {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, nil, err
		}
		var c Config
		if err := json.Unmarshal(b, &c); err != nil {
			return nil, nil, nil, err
		}
		pk, err := base64.StdEncoding.DecodeString(c.PrivKeyB64)
		if err != nil {
			return nil, nil, nil, err
		}
		pub, err := base64.StdEncoding.DecodeString(c.PubKeyB64)
		if err != nil {
			return nil, nil, nil, err
		}
		if c.Accepted == nil {
			c.Accepted = map[string]bool{}
		}
		return &c, ed25519.PrivateKey(pk), ed25519.PublicKey(pub), nil
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	if nick == "" {
		nick = "anon-" + hex.EncodeToString(pub[:4])
	}
	c := &Config{
		Nick:       nick,
		PrivKeyB64: base64.StdEncoding.EncodeToString(priv),
		PubKeyB64:  base64.StdEncoding.EncodeToString(pub),
		Peers:      []string{},
		Accepted:   map[string]bool{},
	}
	if err := saveJSONAtomic(path, c); err != nil {
		return nil, nil, nil, err
	}
	return c, priv, pub, nil
}

func loadOrInitState(path string) (*State, error) {
	if _, err := os.Stat(path); err == nil {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var s State
		if err := json.Unmarshal(b, &s); err != nil {
			return nil, err
		}
		if s.Events == nil {
			s.Events = map[string]Event{}
		}
		return &s, nil
	}
	s := &State{Events: map[string]Event{}, Order: []string{}}
	if err := saveJSONAtomic(path, s); err != nil {
		return nil, err
	}
	return s, nil
}

func getIPv6OnInterface(ifname string) (net.IP, error) {
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, fmt.Errorf("interface %q not found: %w", ifname, err)
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil {
			continue
		}
		ip = ip.To16()
		if ip == nil || ip.To4() != nil {
			continue
		}
		if ip.IsLinkLocalUnicast() {
			continue
		}
		return ip, nil
	}
	return nil, errors.New("no global IPv6 found on interface")
}

func last4(ip net.IP) string {
	if ip == nil {
		return "????"
	}
	b := ip.To16()
	if b == nil {
		return "????"
	}
	he := uint16(b[14])<<8 | uint16(b[15])
	return strings.ToLower(fmt.Sprintf("%04x", he))
}

func last4FromIPv6String(bracketAddr string) string {
	host := bracketAddr
	if i := strings.LastIndex(host, "]"); i >= 0 {
		host = host[:i+1]
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if ip == nil {
		return "????"
	}
	return last4(ip)
}

func shortKey(b64 string) string {
	b, _ := base64.StdEncoding.DecodeString(b64)
	return strings.ToUpper(hex.EncodeToString(b[:3]))
}

// ---------- Events ----------

func eventDigest(e *Event) []byte {
	type bare struct {
		Typ    string `json:"type"`
		Author string `json:"author"`
		Nick   string `json:"nick"`
		Body   string `json:"body"`
		To     string `json:"to,omitempty"`
		TS     int64  `json:"ts"`
	}
	j, _ := json.Marshal(bare{e.Typ, e.Author, e.Nick, e.Body, e.To, e.TS})
	sum := sha256.Sum256(j)
	return sum[:]
}

func signEvent(priv ed25519.PrivateKey, e *Event) {
	d := eventDigest(e)
	id := sha256.Sum256(append([]byte("id:"), d...))
	e.ID = hex.EncodeToString(id[:])
	e.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, d))
}

func verifyEvent(e *Event) error {
	pub, err := base64.StdEncoding.DecodeString(e.Author)
	if err != nil {
		return fmt.Errorf("bad author: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(e.Sig)
	if err != nil {
		return fmt.Errorf("bad sig: %w", err)
	}
	d := eventDigest(e)
	if !ed25519.Verify(ed25519.PublicKey(pub), d, sig) {
		return errors.New("signature verify failed")
	}
	id := sha256.Sum256(append([]byte("id:"), d...))
	if hex.EncodeToString(id[:]) != e.ID {
		return errors.New("id mismatch")
	}
	return nil
}

// ---------- Node helpers ----------

func NewNode(cfgPath, statePath, iface string, port int, nick string) (*Node, error) {
	if dir := filepath.Dir(cfgPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil && !os.IsExist(err) {
			return nil, err
		}
	}
	cfg, priv, pub, err := loadOrInitConfig(cfgPath, nick)
	if err != nil {
		return nil, err
	}
	st, err := loadOrInitState(statePath)
	if err != nil {
		return nil, err
	}
	yip, err := getIPv6OnInterface(iface)
	if err != nil {
		return nil, err
	}

	n := &Node{
		cfgPath:    cfgPath,
		cfg:        cfg,
		statePath:  statePath,
		state:      st,
		iface:      iface,
		yggIP:      yip,
		port:       port,
		priv:       priv,
		pub:        pub,
		peers:      map[string]struct{}{},
		contacts:   map[string]*Contact{},
		pending:    map[string]*Contact{},
		acceptedBy: map[string]bool{},
		quit:       make(chan struct{}),
	}
	for _, p := range cfg.Peers {
		n.peers[p] = struct{}{}
	}
	n.cfg.ListenOn = net.JoinHostPort(yip.String(), fmt.Sprintf("%d", port))
	_ = saveJSONAtomic(cfgPath, n.cfg)
	return n, nil
}

func (n *Node) isAccepted(pub string) bool {
	n.cfgMu.Lock()
	defer n.cfgMu.Unlock()
	return n.cfg.Accepted[pub]
}

func (n *Node) markAccepted(pub, addr, nick string) {
	n.cfgMu.Lock()
	if n.cfg.Accepted == nil {
		n.cfg.Accepted = map[string]bool{}
	}
	n.cfg.Accepted[pub] = true
	_ = saveJSONAtomic(n.cfgPath, n.cfg)
	n.cfgMu.Unlock()

	n.contactsMu.Lock()
	c := n.contacts[pub]
	if c == nil {
		c = &Contact{Pub: pub}
		n.contacts[pub] = c
	}
	if nick != "" {
		c.Nick = nick
	}
	if addr != "" {
		c.Addr = addr
	}
	c.Accepted = true
	c.LastSeen = time.Now()
	n.contactsMu.Unlock()
}

func (n *Node) isAcceptedBy(pub string) bool {
	n.acceptedByMu.Lock()
	defer n.acceptedByMu.Unlock()
	return n.acceptedBy[pub]
}
func (n *Node) markAcceptedBy(pub string) {
	n.acceptedByMu.Lock()
	n.acceptedBy[pub] = true
	n.acceptedByMu.Unlock()
}

func (n *Node) addPeer(addr string) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return
	}
	n.peersMu.Lock()
	if _, ok := n.peers[addr]; ok {
		n.peersMu.Unlock()
		return
	}
	n.peers[addr] = struct{}{}
	n.peersMu.Unlock()
	n.cfgMu.Lock()
	n.cfg.Peers = sortedKeys(n.peers)
	_ = saveJSONAtomic(n.cfgPath, n.cfg)
	n.cfgMu.Unlock()
}

func (n *Node) removePeerAddr(addr string) {
	n.peersMu.Lock()
	delete(n.peers, addr)
	newList := sortedKeys(n.peers)
	n.peersMu.Unlock()
	n.cfgMu.Lock()
	n.cfg.Peers = newList
	_ = saveJSONAtomic(n.cfgPath, n.cfg)
	n.cfgMu.Unlock()
}

func (n *Node) listPeers() []string {
	n.peersMu.Lock()
	defer n.peersMu.Unlock()
	return sortedKeys(n.peers)
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---------- Networking ----------

func (n *Node) listenAndServe() error {
	laddr := &net.TCPAddr{IP: n.yggIP, Port: n.port, Zone: n.iface}
	ln, err := net.ListenTCP("tcp6", laddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", laddr.String(), err)
	}
	defer ln.Close()
	fmt.Printf("[gossipy %s] listening on [%s]:%d (iface=%s)\n", version, n.yggIP.String(), n.port, n.iface)

	go n.peerDialLoop()

	for {
		_ = ln.SetDeadline(time.Now().Add(5 * time.Second))
		c, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-n.quit:
					return nil
				default:
					continue
				}
			}
			fmt.Println("[ERR] accept:", err)
			continue
		}
		go n.handleConn(c)
	}
}

func (n *Node) handleConn(conn net.Conn) {
	defer conn.Close()
	enc := json.NewEncoder(conn)
	dec := bufio.NewScanner(conn)
	dec.Buffer(make([]byte, 0, 65536), 2<<20)

	// Send HELLO
	if err := enc.Encode(WireMsg{
		Kind: "HELLO", Node: n.cfg.PubKeyB64, Nick: n.cfg.Nick, Listen: n.cfg.ListenOn,
	}); err != nil {
		return
	}

	// Expect their HELLO
	if !dec.Scan() {
		return
	}
	var peerHello WireMsg
	if err := json.Unmarshal(dec.Bytes(), &peerHello); err != nil {
		return
	}
	if peerHello.Kind != "HELLO" {
		return
	}
	n.touchContact(peerHello.Node, peerHello.Nick, peerHello.Listen)

	// Send HAVE
	if err := enc.Encode(WireMsg{Kind: "HAVE", IDs: n.lastIDs(128)}); err != nil {
		return
	}

	for {
		if !dec.Scan() {
			if err := dec.Err(); err != nil && err != io.EOF {
				fmt.Println("[peer read]", err)
			}
			return
		}
		var m WireMsg
		if err := json.Unmarshal(dec.Bytes(), &m); err != nil {
			return
		}
		switch m.Kind {
		case "HAVE":
			missing := n.missingOf(m.IDs)
			if len(missing) > 0 {
				_ = enc.Encode(WireMsg{Kind: "WANT", IDs: missing})
			}
		case "WANT":
			n.stateMu.Lock()
			for _, id := range m.IDs {
				if e, ok := n.state.Events[id]; ok {
					if err := enc.Encode(WireMsg{Kind: "EVENT", Event: &e}); err != nil {
						n.stateMu.Unlock()
						return
					}
				}
			}
			n.stateMu.Unlock()
		case "EVENT":
			if m.Event != nil {
				n.ingestEvent(*m.Event, false)
			}
		case "PEER_REQ":
			// If we already accepted them, auto-ACK and don't spam.
			if n.isAccepted(m.Node) {
				_ = enc.Encode(WireMsg{Kind: "PEER_ACK", Node: n.cfg.PubKeyB64, Nick: n.cfg.Nick, Listen: n.cfg.ListenOn})
				continue
			}
			addr := m.Listen
			n.contactsMu.Lock()
			c := n.contacts[m.Node]
			if c == nil {
				c = &Contact{Pub: m.Node}
				n.contacts[m.Node] = c
			}
			if m.Nick != "" {
				c.Nick = m.Nick
			}
			if addr != "" {
				c.Addr = addr
			}
			now := time.Now()
			shouldPrint := now.Sub(c.LastPrint) > 60*time.Second
			c.LastSeen = now
			if shouldPrint {
				c.LastPrint = now
			}
			n.contactsMu.Unlock()
			n.pendingMu.Lock()
			n.pending[m.Node] = &Contact{Pub: m.Node, Nick: m.Nick, Addr: addr, LastSeen: time.Now()}
			n.pendingMu.Unlock()
			if shouldPrint {
				fmt.Printf("[request] %s (%s) asks to peer: %s — /accept %s\n",
					n.prettyContact(c), shortKey(m.Node), displayAddr(addr), shortKey(m.Node))
			}
		case "PEER_ACK":
			n.markAcceptedBy(m.Node)
			// optional toast (once)
			n.contactsMu.Lock()
			c := n.contacts[m.Node]
			n.contactsMu.Unlock()
			if c != nil {
				fmt.Printf("[ok] %s (%s) accepted you\n", n.prettyContact(c), shortKey(m.Node))
			} else {
				fmt.Printf("[ok] peer accepted you (%s)\n", shortKey(m.Node))
			}
		default:
			// ignore
		}
	}
}

func (n *Node) dialOnce(addr string) {
	if !strings.Contains(addr, ":") {
		return
	}
	d := net.Dialer{
		LocalAddr: &net.TCPAddr{IP: n.yggIP, Port: 0, Zone: n.iface},
		Timeout:   5 * time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return
	}
	defer conn.Close()

	dec := bufio.NewScanner(conn)
	dec.Buffer(make([]byte, 0, 65536), 2<<20)
	enc := json.NewEncoder(conn)

	// Read server HELLO
	if !dec.Scan() {
		return
	}
	var ph WireMsg
	if err := json.Unmarshal(dec.Bytes(), &ph); err != nil {
		return
	}
	if ph.Kind != "HELLO" {
		return
	}
	n.touchContact(ph.Node, ph.Nick, ph.Listen)

	// Send HELLO
	if err := enc.Encode(WireMsg{Kind: "HELLO", Node: n.cfg.PubKeyB64, Nick: n.cfg.Nick, Listen: n.cfg.ListenOn}); err != nil {
		return
	}

	// IMPORTANT: send PEER_REQ until they PEER_ACK us (mutual handshake)
	if !n.isAcceptedBy(ph.Node) {
		_ = enc.Encode(WireMsg{Kind: "PEER_REQ", Node: n.cfg.PubKeyB64, Nick: n.cfg.Nick, Listen: n.cfg.ListenOn})
	}

	// Read HAVE
	if !dec.Scan() {
		return
	}
	var have WireMsg
	if err := json.Unmarshal(dec.Bytes(), &have); err != nil {
		return
	}
	if have.Kind != "HAVE" {
		return
	}

	// Send WANT
	missing := n.missingOf(have.IDs)
	if len(missing) > 0 {
		_ = enc.Encode(WireMsg{Kind: "WANT", IDs: missing})
	}

	// Receive EVENTS/ACKs briefly
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	for dec.Scan() {
		var m WireMsg
		if err := json.Unmarshal(dec.Bytes(), &m); err != nil {
			break
		}
		switch m.Kind {
		case "EVENT":
			if m.Event != nil {
				n.ingestEvent(*m.Event, false)
			}
		case "PEER_ACK":
			n.markAcceptedBy(m.Node)
		}
	}
}

// One-shot dial just to deliver a PEER_ACK after /accept (best effort).
func (n *Node) dialAndAck(addr string) {
	if addr == "" {
		return
	}
	d := net.Dialer{
		LocalAddr: &net.TCPAddr{IP: n.yggIP, Port: 0, Zone: n.iface},
		Timeout:   5 * time.Second,
	}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return
	}
	defer conn.Close()
	dec := bufio.NewScanner(conn)
	dec.Buffer(make([]byte, 0, 65536), 2<<20)
	enc := json.NewEncoder(conn)

	// Read server HELLO
	if !dec.Scan() {
		return
	}
	var ph WireMsg
	if err := json.Unmarshal(dec.Bytes(), &ph); err != nil {
		return
	}
	if ph.Kind != "HELLO" {
		return
	}

	// Send HELLO + PEER_ACK
	_ = enc.Encode(WireMsg{Kind: "HELLO", Node: n.cfg.PubKeyB64, Nick: n.cfg.Nick, Listen: n.cfg.ListenOn})
	_ = enc.Encode(WireMsg{Kind: "PEER_ACK", Node: n.cfg.PubKeyB64, Nick: n.cfg.Nick, Listen: n.cfg.ListenOn})
}

func (n *Node) peerDialLoop() {
	t := time.NewTicker(7 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-n.quit:
			return
		case <-t.C:
			for _, p := range n.listPeers() {
				go n.dialOnce(p)
			}
		}
	}
}

func (n *Node) touchContact(pub, nick, addr string) {
	if pub == "" {
		return
	}
	n.contactsMu.Lock()
	defer n.contactsMu.Unlock()
	c := n.contacts[pub]
	if c == nil {
		c = &Contact{Pub: pub}
		n.contacts[pub] = c
	}
	if nick != "" {
		c.Nick = nick
	}
	if addr != "" {
		c.Addr = addr
	}
	c.Accepted = n.isAccepted(pub)
	c.LastSeen = time.Now()
}

func (n *Node) prettyContact(c *Contact) string {
	lf := "????"
	if c.Addr != "" {
		lf = last4FromIPv6String(c.Addr)
	}
	nk := c.Nick
	if nk == "" {
		nk = "anon"
	}
	return fmt.Sprintf("%s@%s", nk, lf)
}

func displayAddr(addr string) string {
	if addr == "" {
		return "(no-addr)"
	}
	return addr
}

// ---------- Gossip storage ----------

func (n *Node) lastIDs(max int) []string {
	n.stateMu.Lock()
	defer n.stateMu.Unlock()
	if len(n.state.Order) <= max {
		return append([]string{}, n.state.Order...)
	}
	return append([]string{}, n.state.Order[len(n.state.Order)-max:]...)
}

func (n *Node) missingOf(peerIDs []string) []string {
	n.stateMu.Lock()
	defer n.stateMu.Unlock()
	missing := []string{}
	for _, id := range peerIDs {
		if _, ok := n.state.Events[id]; !ok {
			missing = append(missing, id)
		}
	}
	return missing
}

func (n *Node) ingestEvent(e Event, local bool) {
	if err := verifyEvent(&e); err != nil {
		fmt.Println("[WARN] drop bad event:", err)
		return
	}
	n.touchContact(e.Author, e.Nick, "")
	n.stateMu.Lock()
	if _, ok := n.state.Events[e.ID]; ok {
		n.stateMu.Unlock()
		return
	}
	n.state.Events[e.ID] = e
	n.state.Order = append(n.state.Order, e.ID)
	n.stateMu.Unlock()
	_ = saveJSONAtomic(n.statePath, n.state)

	switch e.Typ {
	case "msg":
		fmt.Printf("[%s][global] %s: %s\n", time.Unix(e.TS, 0).Format("15:04:05"), displayFrom(e.Nick, e.Author), e.Body)
	case "dm":
		if e.Author == n.cfg.PubKeyB64 {
			fmt.Printf("[%s] ✉️ to %s: %s\n", time.Unix(e.TS, 0).Format("15:04:05"), targetLabel(n, e.To), e.Body)
		} else if e.To == n.cfg.PubKeyB64 {
			fmt.Printf("[%s] ✉️ from %s: %s\n", time.Unix(e.TS, 0).Format("15:04:05"), displayFrom(e.Nick, e.Author), e.Body)
			n.lastDMFromMu.Lock()
			n.lastDMFrom = e.Author
			n.lastDMFromMu.Unlock()
		}
	}
}

func displayFrom(nick, authorB64 string) string {
	pub, _ := base64.StdEncoding.DecodeString(authorB64)
	hexid := strings.ToUpper(hex.EncodeToString(pub[:3]))
	if nick == "" {
		nick = "anon"
	}
	return fmt.Sprintf("%s~%s", nick, hexid)
}

func targetLabel(n *Node, toB64 string) string {
	n.contactsMu.Lock()
	defer n.contactsMu.Unlock()
	if c := n.contacts[toB64]; c != nil && c.Nick != "" {
		return fmt.Sprintf("%s~%s", c.Nick, shortKey(toB64))
	}
	return "~" + shortKey(toB64)
}

// ---------- Send helpers ----------

func (n *Node) sendGlobal(body string) {
	ev := &Event{Typ: "msg", Author: n.cfg.PubKeyB64, Nick: n.cfg.Nick, Body: body, TS: time.Now().Unix()}
	signEvent(n.priv, ev)
	n.ingestEvent(*ev, true)
}

func (n *Node) sendDM(targetPubB64, body string) {
	ev := &Event{Typ: "dm", Author: n.cfg.PubKeyB64, Nick: n.cfg.Nick, Body: body, To: targetPubB64, TS: time.Now().Unix()}
	signEvent(n.priv, ev)
	n.ingestEvent(*ev, true)
}

// ---------- Links & QR ----------

func (n *Node) buildLink() string {
	u := &url.URL{Scheme: "gossipy", Host: fmt.Sprintf("[%s]:%d", n.yggIP.String(), n.port)}
	q := url.Values{}
	q.Set("id", base64.RawURLEncoding.EncodeToString(n.pub))
	q.Set("nick", n.cfg.Nick)
	u.RawQuery = q.Encode()
	return u.String()
}

func (n *Node) showLinkQR() {
	link := n.buildLink()
	fmt.Println("Share this link (or QR) so friends can connect & send you a peer request:")
	fmt.Println(link, "\n")
	qrterminal.GenerateWithConfig(link, qrterminal.Config{
		Level: qrterminal.M, Writer: os.Stdout, BlackChar: qrterminal.BLACK, WhiteChar: qrterminal.WHITE, QuietZone: 1,
	})
	fmt.Println()
}

func parseLink(s string) (addr, pubB64, nick string, err error) {
	if !strings.HasPrefix(s, "gossipy://") {
		return "", "", "", errors.New("not a gossipy:// link")
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", "", "", err
	}
	addr = u.Host
	if !strings.Contains(addr, "]") {
		return "", "", "", errors.New("bad host (need [IPv6]:port)")
	}
	id := u.Query().Get("id")
	if id != "" {
		if b, err2 := base64.RawURLEncoding.DecodeString(id); err2 == nil {
			pubB64 = base64.StdEncoding.EncodeToString(b)
		}
	}
	nick = u.Query().Get("nick")
	return addr, pubB64, nick, nil
}

// ---------- REPL ----------

func (n *Node) repl() {
	in := bufio.NewReader(os.Stdin)
	fmt.Printf("Type text to chat [global]. Use /help for commands.\n")
	for {
		fmt.Printf("[%s@%s] > ", n.cfg.Nick, last4(n.yggIP))
		line, err := in.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				fmt.Println()
				close(n.quit)
				return
			}
			fmt.Println("[read err]", err)
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "/") {
			n.handleCommand(line)
			continue
		}
		n.sendGlobal(line)
	}
}

func (n *Node) handleCommand(line string) {
	parts := strings.Fields(line)
	cmd := strings.ToLower(strings.TrimPrefix(parts[0], "/"))
	switch cmd {
	case "help":
		fmt.Println(`Commands:
  /link
  /accept <gossipy://... | pubkey | SHORTID>
  /pending
  /contacts
  /peers
  /unpeer <pub|SHORTID>
  /nick <name>
  /msg <who> <text>
  /r <text>
  /save
  /quit`)
	case "link":
		n.showLinkQR()
	case "pending":
		n.pendingMu.Lock()
		if len(n.pending) == 0 {
			fmt.Println("(no pending requests)")
		}
		for pub, c := range n.pending {
			fmt.Printf(" - %s (%s) addr=%s seen=%s\n",
				displayFrom(c.Nick, pub), shortKey(pub), displayAddr(c.Addr), c.LastSeen.Format("15:04:05"))
		}
		n.pendingMu.Unlock()
	case "contacts":
		n.contactsMu.Lock()
		if len(n.contacts) == 0 {
			fmt.Println("(no contacts yet)")
		} else {
			keys := make([]string, 0, len(n.contacts))
			for k := range n.contacts {
				keys = append(keys, k)
			}
			sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
			for _, pub := range keys {
				c := n.contacts[pub]
				acc := "no"
				if c.Accepted {
					acc = "yes"
				}
				fmt.Printf(" - %s (%s) addr=%s accepted=%s\n",
					displayFrom(c.Nick, pub), shortKey(pub), displayAddr(c.Addr), acc)
			}
		}
		n.contactsMu.Unlock()
	case "accept":
		if len(parts) < 2 {
			fmt.Println("usage: /accept <gossipy://... | pubkey | SHORTID>")
			return
		}
		arg := strings.TrimSpace(strings.TrimPrefix(line, "/accept"))
		if strings.HasPrefix(arg, "gossipy://") {
			addr, pub, nick, err := parseLink(arg)
			if err != nil {
				fmt.Println("[err]", err)
				return
			}
			n.addPeer(addr)
			if pub != "" {
				n.markAccepted(pub, addr, nick)
				fmt.Printf("[ok] added peer %s and accepted %s (%s)\n", displayAddr(addr), nickOrShort(pub, nick), shortKey(pub))
				go n.dialAndAck(addr) // tell them we accepted
			} else {
				fmt.Printf("[ok] added peer %s\n", displayAddr(addr))
			}
			return
		}
		// pub or SHORTID
		targetPub := n.resolveByPubOrShort(arg)
		if targetPub == "" {
			n.pendingMu.Lock()
			if _, ok := n.pending[arg]; ok {
				targetPub = arg
			}
			n.pendingMu.Unlock()
		}
		if targetPub == "" {
			fmt.Println("[err] no pending or known contact:", arg)
			return
		}
		var addr, nick string
		n.pendingMu.Lock()
		if p := n.pending[targetPub]; p != nil {
			addr = p.Addr
			nick = p.Nick
			delete(n.pending, targetPub)
		}
		n.pendingMu.Unlock()
		n.contactsMu.Lock()
		if c := n.contacts[targetPub]; c != nil {
			if addr == "" {
				addr = c.Addr
			}
			if nick == "" {
				nick = c.Nick
			}
		}
		n.contactsMu.Unlock()
		n.markAccepted(targetPub, addr, nick)
		if addr != "" {
			n.addPeer(addr)
			go n.dialAndAck(addr)
		}
		fmt.Printf("[ok] accepted %s (%s)%s\n", nickOrShort(targetPub, nick), shortKey(targetPub), optionalAddr(addr))
	case "unpeer":
		if len(parts) < 2 {
			fmt.Println("usage: /unpeer <pub|SHORTID>")
			return
		}
		pub := n.resolveByPubOrShort(parts[1])
		if pub == "" {
			fmt.Println("[err] unknown contact")
			return
		}
		n.cfgMu.Lock()
		delete(n.cfg.Accepted, pub)
		_ = saveJSONAtomic(n.cfgPath, n.cfg)
		n.cfgMu.Unlock()
		n.contactsMu.Lock()
		addr := ""
		if c := n.contacts[pub]; c != nil {
			addr = c.Addr
			c.Accepted = false
		}
		n.contactsMu.Unlock()
		if addr != "" {
			n.removePeerAddr(addr)
		}
		fmt.Printf("[ok] unpeered %s (%s)\n", nickOrShort(pub, ""), shortKey(pub))
	case "peers":
		for _, p := range n.listPeers() {
			fmt.Println(" -", p)
		}
	case "nick":
		if len(parts) < 2 {
			fmt.Println("usage: /nick <name>")
			return
		}
		newNick := strings.TrimSpace(strings.TrimPrefix(line, "/nick"))
		n.cfgMu.Lock()
		n.cfg.Nick = newNick
		_ = saveJSONAtomic(n.cfgPath, n.cfg)
		n.cfgMu.Unlock()
		fmt.Println("[ok] nick set")
	case "msg":
		if len(parts) < 3 {
			fmt.Println("usage: /msg <who> <text>")
			return
		}
		who := parts[1]
		text := strings.TrimSpace(strings.TrimPrefix(line, "/msg"))
		if i := strings.Index(text, who); i >= 0 {
			text = strings.TrimSpace(text[i+len(who):])
		}
		pub := n.resolveWho(who)
		if pub == "" {
			fmt.Println("[err] unknown recipient:", who)
			return
		}
		n.sendDM(pub, text)
	case "r":
		if len(parts) < 2 {
			fmt.Println("usage: /r <text>")
			return
		}
		n.lastDMFromMu.Lock()
		target := n.lastDMFrom
		n.lastDMFromMu.Unlock()
		if target == "" {
			fmt.Println("[err] no recent *incoming* DM. Use /msg <who> <text>.")
			return
		}
		text := strings.TrimSpace(strings.TrimPrefix(line, "/r"))
		n.sendDM(target, text)
	case "save":
		_ = saveJSONAtomic(n.statePath, n.state)
		fmt.Println("[ok] saved")
	case "quit", "exit":
		close(n.quit)
	default:
		fmt.Println("unknown command. /help for help")
	}
}

func (n *Node) resolveByPubOrShort(s string) string {
	if strings.Contains(s, "=") && len(s) > 40 {
		return s
	}
	n.contactsMu.Lock()
	defer n.contactsMu.Unlock()
	for pub := range n.contacts {
		if strings.EqualFold(shortKey(pub), s) {
			return pub
		}
	}
	return ""
}

func (n *Node) resolveWho(who string) string {
	if strings.Contains(who, "=") && len(who) > 40 {
		return who
	}
	n.contactsMu.Lock()
	defer n.contactsMu.Unlock()
	for pub, c := range n.contacts {
		if strings.EqualFold(shortKey(pub), who) || (c.Nick != "" && strings.EqualFold(c.Nick, who)) {
			return pub
		}
	}
	return ""
}

// ---------- main ----------

func main() {
	var (
		iface = flag.String("iface", "tun0", "Yggdrasil interface (e.g. tun0 or ygg0)")
		port  = flag.Int("port", 19999, "TCP port to listen on (IPv6)")
		state = flag.String("state", "./gossipy_state.json", "Path to state JSON")
		conf  = flag.String("config", "./gossipy_config.json", "Path to config JSON")
		nick  = flag.String("nick", "", "Nickname (optional)")
		peer  = flag.String("peer", "", "Add a peer on startup ([IPv6]:port)")
	)
	flag.Parse()

	node, err := NewNode(*conf, *state, *iface, *port, *nick)
	if err != nil {
		fmt.Println("init error:", err)
		os.Exit(1)
	}
	if *peer != "" {
		node.addPeer(*peer)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	go func() {
		if err := node.listenAndServe(); err != nil {
			fmt.Println("server error:", err)
			close(node.quit)
		}
	}()

	fmt.Printf("gossipy v%s | nick=%q | id=%s\n", version, node.cfg.Nick, shortKey(node.cfg.PubKeyB64))
	fmt.Printf("Address: [%s]:%d (iface=%s)\n", node.yggIP.String(), node.port, node.iface)
	fmt.Printf("Peers: %v\n", node.listPeers())
	fmt.Println("Tip: /link to print a QR; /accept <gossipy://…> to connect; /pending then /accept <SHORTID> to approve.\n")

	go node.repl()

	select {
	case <-ctx.Done():
	case <-node.quit:
	}
	fmt.Println("\nshutting down...")
}

// ---------- small format helpers ----------

func nickOrShort(pub, nick string) string {
	if nick != "" {
		return nick
	}
	return "~" + shortKey(pub)
}
func optionalAddr(addr string) string {
	if addr == "" {
		return ""
	}
	return " and added peer " + addr
}
