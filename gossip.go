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
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/nacl/box"
)

const Version = "0.4"

// ---------- Config & State ----------

type Config struct {
	Nick        string            `json:"nick"`
	PrivKeyB64  string            `json:"privkey"`
	PubKeyB64   string            `json:"pubkey"`
	EncPrivB64  string            `json:"enc_privkey"`
	EncPubB64   string            `json:"enc_pubkey"`
	Peers       []string          `json:"peers"`
	ListenOn    string            `json:"listen_on"`
	Accepted    map[string]bool   `json:"accepted"`
	ContactEKey map[string]string `json:"contact_ekeys"`
}

type KeyWrap struct {
	N  string `json:"n"`
	CT string `json:"ct"`
}

type EncPayload struct {
	Scheme string             `json:"scheme"`
	SPK    string             `json:"spk"`
	N      string             `json:"n"`
	CT     string             `json:"ct"`
	Keys   map[string]KeyWrap `json:"keys"`
}

type Event struct {
	ID     string      `json:"id"`
	Typ    string      `json:"type"`
	Author string      `json:"author"`
	Nick   string      `json:"nick"`
	Body   string      `json:"body,omitempty"`
	Enc    *EncPayload `json:"enc,omitempty"`
	To     string      `json:"to,omitempty"`
	TS     int64       `json:"ts"`
	Sig    string      `json:"sig"`
}

type State struct {
	Events map[string]Event `json:"events"`
	Order  []string         `json:"order"`
}

type WireMsg struct {
	Kind   string   `json:"kind"`
	Node   string   `json:"node,omitempty"`
	Nick   string   `json:"nick,omitempty"`
	Listen string   `json:"listen,omitempty"`
	EKey   string   `json:"ekey,omitempty"`
	IDs    []string `json:"ids,omitempty"`
	Event  *Event   `json:"event,omitempty"`
}

type Contact struct {
	Pub       string
	Nick      string
	Addr      string
	EncPub    string
	LastSeen  time.Time
	Accepted  bool
	LastPrint time.Time
}

// Event types for the event handler
type EventType int

const (
	EventMessage EventType = iota
	EventDM
	EventPeerRequest
	EventPeerAccepted
	EventError
)

type EventHandler func(EventType, interface{})

// Message event data
type MessageEvent struct {
	Timestamp time.Time
	Author    string
	Nick      string
	Body      string
	Encrypted bool
}

// DM event data
type DMEvent struct {
	Timestamp time.Time
	Author    string
	Nick      string
	To        string
	Body      string
	Encrypted bool
	Incoming  bool
}

// Peer request event data
type PeerRequestEvent struct {
	Pub  string
	Nick string
	Addr string
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

	encPriv *[32]byte
	encPub  *[32]byte

	peersMu sync.Mutex
	peers   map[string]struct{}

	contactsMu sync.Mutex
	contacts   map[string]*Contact

	pendingMu sync.Mutex
	pending   map[string]*Contact

	acceptedByMu sync.Mutex
	acceptedBy   map[string]bool

	lastDMFromMu sync.Mutex
	lastDMFrom   string

	quit         chan struct{}
	eventHandler EventHandler
}

// ---------- Public API ----------

func NewNode(cfgPath, statePath, iface string, port int, nick string) (*Node, error) {
	if dir := filepath.Dir(cfgPath); dir != `` && dir != `.` {
		if err := os.MkdirAll(dir, 0o755); err != nil && !os.IsExist(err) {
			return nil, err
		}
	}
	cfg, priv, pub, encPriv, encPub, err := loadOrInitConfig(cfgPath, nick)
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
		encPriv:    encPriv,
		encPub:     encPub,
		peers:      map[string]struct{}{},
		contacts:   map[string]*Contact{},
		pending:    map[string]*Contact{},
		acceptedBy: map[string]bool{},
		quit:       make(chan struct{}),
	}
	for _, p := range cfg.Peers {
		n.peers[p] = struct{}{}
	}
	for edpub, ekey := range cfg.ContactEKey {
		if edpub == `` || ekey == `` {
			continue
		}
		n.contacts[edpub] = &Contact{Pub: edpub, EncPub: ekey, Accepted: n.isAccepted(edpub)}
	}

	n.cfg.ListenOn = net.JoinHostPort(yip.String(), fmt.Sprintf(`%d`, port))
	_ = saveJSONAtomic(cfgPath, n.cfg)
	return n, nil
}

func (n *Node) SetEventHandler(handler EventHandler) {
	n.eventHandler = handler
}

func (n *Node) GetConfig() Config {
	n.cfgMu.Lock()
	defer n.cfgMu.Unlock()
	return *n.cfg
}

func (n *Node) GetNick() string {
	n.cfgMu.Lock()
	defer n.cfgMu.Unlock()
	return n.cfg.Nick
}

func (n *Node) SetNick(nick string) {
	n.cfgMu.Lock()
	n.cfg.Nick = nick
	_ = saveJSONAtomic(n.cfgPath, n.cfg)
	n.cfgMu.Unlock()
}

func (n *Node) GetPublicKeyB64() string {
	return n.cfg.PubKeyB64
}

func (n *Node) GetYggIP() net.IP {
	return n.yggIP
}

func (n *Node) GetPort() int {
	return n.port
}

func (n *Node) GetInterface() string {
	return n.iface
}

func (n *Node) BuildLink() string {
	u := &url.URL{Scheme: `gossip`, Host: fmt.Sprintf(`[%s]:%d`, n.yggIP.String(), n.port)}
	q := url.Values{}
	q.Set(`id`, base64.RawURLEncoding.EncodeToString(n.pub))
	q.Set(`nick`, n.cfg.Nick)
	u.RawQuery = q.Encode()
	return u.String()
}

func (n *Node) GetPendingRequests() []Contact {
	n.pendingMu.Lock()
	defer n.pendingMu.Unlock()
	result := make([]Contact, 0, len(n.pending))
	for _, c := range n.pending {
		result = append(result, *c)
	}
	return result
}

func (n *Node) GetContacts() []Contact {
	n.contactsMu.Lock()
	defer n.contactsMu.Unlock()
	result := make([]Contact, 0, len(n.contacts))
	for _, c := range n.contacts {
		result = append(result, *c)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Pub < result[j].Pub
	})
	return result
}

func (n *Node) ListPeers() []string {
	n.peersMu.Lock()
	defer n.peersMu.Unlock()
	return sortedKeys(n.peers)
}

func (n *Node) AddPeer(addr string) {
	n.addPeer(addr)
}

func (n *Node) AcceptPeerByLink(link string) error {
	addr, pub, nick, err := ParseLink(link)
	if err != nil {
		return err
	}
	n.addPeer(addr)
	if pub != `` {
		n.markAccepted(pub, addr, nick)
		go n.dialAndAck(addr)
	}
	return nil
}

func (n *Node) AcceptPeer(pubOrShortID string) error {
	targetPub := n.ResolveByPubOrShort(pubOrShortID)
	if targetPub == `` {
		n.pendingMu.Lock()
		if _, ok := n.pending[pubOrShortID]; ok {
			targetPub = pubOrShortID
		}
		n.pendingMu.Unlock()
	}
	if targetPub == `` {
		return fmt.Errorf("no pending or known contact: %s", pubOrShortID)
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
		if addr == `` {
			addr = c.Addr
		}
		if nick == `` {
			nick = c.Nick
		}
	}
	n.contactsMu.Unlock()
	n.markAccepted(targetPub, addr, nick)
	if addr != `` {
		n.addPeer(addr)
		go n.dialAndAck(addr)
	}
	return nil
}

func (n *Node) UnpeerContact(pubOrShortID string) error {
	pub := n.ResolveByPubOrShort(pubOrShortID)
	if pub == `` {
		return errors.New("unknown contact")
	}
	n.cfgMu.Lock()
	delete(n.cfg.Accepted, pub)
	_ = saveJSONAtomic(n.cfgPath, n.cfg)
	n.cfgMu.Unlock()
	n.contactsMu.Lock()
	addr := ``
	if c := n.contacts[pub]; c != nil {
		addr = c.Addr
		c.Accepted = false
	}
	n.contactsMu.Unlock()
	if addr != `` {
		n.removePeerAddr(addr)
	}
	return nil
}

func (n *Node) SendGlobal(body string) {
	recip := n.recipientsForGlobal()
	enc, err := n.encryptForRecipients([]byte(body), recip)
	if err != nil {
		if n.eventHandler != nil {
			n.eventHandler(EventError, fmt.Errorf("encrypt global: %w", err))
		}
		return
	}
	ev := &Event{Typ: `msg`, Author: n.cfg.PubKeyB64, Nick: n.cfg.Nick, Enc: enc, TS: time.Now().Unix()}
	signEvent(n.priv, ev)
	n.ingestEvent(*ev, true)
}

func (n *Node) SendDM(targetPubB64, body string) error {
	recip := map[string]string{n.cfg.PubKeyB64: n.encPubB64()}
	if encPub, ok := n.getEncPubFor(targetPubB64); ok {
		recip[targetPubB64] = encPub
	} else {
		return errors.New("recipient has no encryption key yet; try after they connect once")
	}
	enc, err := n.encryptForRecipients([]byte(body), recip)
	if err != nil {
		return fmt.Errorf("encrypt dm: %w", err)
	}
	ev := &Event{Typ: `dm`, Author: n.cfg.PubKeyB64, Nick: n.cfg.Nick, To: targetPubB64, Enc: enc, TS: time.Now().Unix()}
	signEvent(n.priv, ev)
	n.ingestEvent(*ev, true)
	return nil
}

func (n *Node) SendDMByWho(who, body string) error {
	pub := n.ResolveWho(who)
	if pub == `` {
		return fmt.Errorf("unknown recipient: %s", who)
	}
	return n.SendDM(pub, body)
}

func (n *Node) ReplyToLastDM(body string) error {
	n.lastDMFromMu.Lock()
	target := n.lastDMFrom
	n.lastDMFromMu.Unlock()
	if target == `` {
		return errors.New("no recent incoming DM")
	}
	return n.SendDM(target, body)
}

func (n *Node) SaveState() error {
	return saveJSONAtomic(n.statePath, n.state)
}

func (n *Node) Shutdown() {
	close(n.quit)
}

func (n *Node) ListenAndServe() error {
	return n.listenAndServe()
}

func (n *Node) ResolveByPubOrShort(s string) string {
	if strings.Contains(s, `=`) && len(s) > 40 {
		return s
	}
	n.contactsMu.Lock()
	defer n.contactsMu.Unlock()
	for pub := range n.contacts {
		if strings.EqualFold(ShortKey(pub), s) {
			return pub
		}
	}
	return ``
}

func (n *Node) ResolveWho(who string) string {
	if strings.Contains(who, `=`) && len(who) > 40 {
		return who
	}
	n.contactsMu.Lock()
	defer n.contactsMu.Unlock()
	for pub, c := range n.contacts {
		if strings.EqualFold(ShortKey(pub), who) || (c.Nick != `` && strings.EqualFold(c.Nick, who)) {
			return pub
		}
	}
	return ``
}

// ---------- Utils (exported for CLI) ----------

func ShortKey(b64 string) string {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(b) < 3 {
		return `BADKEY`
	}
	return strings.ToUpper(hex.EncodeToString(b[:3]))
}

func ParseLink(s string) (addr, pubB64, nick string, err error) {
	if !strings.HasPrefix(s, `gossip://`) {
		return ``, ``, ``, errors.New(`not a gossip:// link`)
	}
	u, err := url.Parse(s)
	if err != nil {
		return ``, ``, ``, err
	}
	addr = u.Host
	if !strings.Contains(addr, `]`) {
		return ``, ``, ``, errors.New(`bad host (need [IPv6]:port)`)
	}
	id := u.Query().Get(`id`)
	if id != `` {
		if b, err2 := base64.RawURLEncoding.DecodeString(id); err2 == nil {
			pubB64 = base64.StdEncoding.EncodeToString(b)
		}
	}
	nick = u.Query().Get(`nick`)
	return addr, pubB64, nick, nil
}

// ---------- Private methods ----------

func saveJSONAtomic(path string, v any) error {
	tmp := path + `.tmp`
	b, err := json.MarshalIndent(v, ``, `  `)
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func decodeB64To32(s string) (*[32]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, fmt.Errorf(`want 32 bytes, got %d`, len(b))
	}
	var out [32]byte
	copy(out[:], b)
	return &out, nil
}

func loadOrInitConfig(path string, nick string) (*Config, ed25519.PrivateKey, ed25519.PublicKey, *[32]byte, *[32]byte, error) {
	if _, err := os.Stat(path); err == nil {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		var c Config
		if err := json.Unmarshal(b, &c); err != nil {
			return nil, nil, nil, nil, nil, err
		}
		pk, err := base64.StdEncoding.DecodeString(c.PrivKeyB64)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		pub, err := base64.StdEncoding.DecodeString(c.PubKeyB64)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		if c.EncPrivB64 == `` || c.EncPubB64 == `` {
			pubE, privE, err := box.GenerateKey(rand.Reader)
			if err != nil {
				return nil, nil, nil, nil, nil, err
			}
			c.EncPrivB64 = base64.StdEncoding.EncodeToString(privE[:])
			c.EncPubB64 = base64.StdEncoding.EncodeToString(pubE[:])
		}
		if c.ContactEKey == nil {
			c.ContactEKey = map[string]string{}
		}
		if c.Accepted == nil {
			c.Accepted = map[string]bool{}
		}
		_ = saveJSONAtomic(path, &c)
		encPriv, err := decodeB64To32(c.EncPrivB64)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		encPub, err := decodeB64To32(c.EncPubB64)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		return &c, ed25519.PrivateKey(pk), ed25519.PublicKey(pub), encPriv, encPub, nil
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	pubE, privE, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	if nick == `` {
		nick = `anon-` + hex.EncodeToString(pub[:4])
	}
	c := &Config{
		Nick:        nick,
		PrivKeyB64:  base64.StdEncoding.EncodeToString(priv),
		PubKeyB64:   base64.StdEncoding.EncodeToString(pub),
		EncPrivB64:  base64.StdEncoding.EncodeToString(privE[:]),
		EncPubB64:   base64.StdEncoding.EncodeToString(pubE[:]),
		Peers:       []string{},
		Accepted:    map[string]bool{},
		ContactEKey: map[string]string{},
	}
	if err := saveJSONAtomic(path, c); err != nil {
		return nil, nil, nil, nil, nil, err
	}
	return c, priv, pub, privE, pubE, nil
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
		return nil, fmt.Errorf(`interface %q not found: %w`, ifname, err)
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
	return nil, errors.New(`no global IPv6 found on interface`)
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
	if nick != `` {
		c.Nick = nick
	}
	if addr != `` {
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
	if addr == `` {
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
	ln, err := net.ListenTCP(`tcp6`, laddr)
	if err != nil {
		return fmt.Errorf(`listen on %s: %w`, laddr.String(), err)
	}
	defer ln.Close()

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

	if err := enc.Encode(WireMsg{Kind: `HELLO`, Node: n.cfg.PubKeyB64, Nick: n.cfg.Nick, Listen: n.cfg.ListenOn, EKey: base64.StdEncoding.EncodeToString(n.encPub[:])}); err != nil {
		return
	}

	if !dec.Scan() {
		return
	}
	var peerHello WireMsg
	if err := json.Unmarshal(dec.Bytes(), &peerHello); err != nil {
		return
	}
	if peerHello.Kind != `HELLO` {
		return
	}
	n.touchContact(peerHello.Node, peerHello.Nick, peerHello.Listen, peerHello.EKey)

	if err := enc.Encode(WireMsg{Kind: `HAVE`, IDs: n.lastIDs(128)}); err != nil {
		return
	}

	for {
		if !dec.Scan() {
			return
		}
		var m WireMsg
		if err := json.Unmarshal(dec.Bytes(), &m); err != nil {
			return
		}
		switch m.Kind {
		case `HAVE`:
			missing := n.missingOf(m.IDs)
			if len(missing) > 0 {
				_ = enc.Encode(WireMsg{Kind: `WANT`, IDs: missing})
			}
		case `WANT`:
			n.stateMu.Lock()
			for _, id := range m.IDs {
				if e, ok := n.state.Events[id]; ok {
					if err := enc.Encode(WireMsg{Kind: `EVENT`, Event: &e}); err != nil {
						n.stateMu.Unlock()
						return
					}
				}
			}
			n.stateMu.Unlock()
		case `EVENT`:
			if m.Event != nil {
				n.ingestEvent(*m.Event, false)
			}
		case `PEER_REQ`:
			if n.isAccepted(m.Node) {
				_ = enc.Encode(WireMsg{Kind: `PEER_ACK`, Node: n.cfg.PubKeyB64, Nick: n.cfg.Nick, Listen: n.cfg.ListenOn, EKey: base64.StdEncoding.EncodeToString(n.encPub[:])})
				continue
			}
			addr := m.Listen
			n.contactsMu.Lock()
			c := n.contacts[m.Node]
			if c == nil {
				c = &Contact{Pub: m.Node}
				n.contacts[m.Node] = c
			}
			if m.Nick != `` {
				c.Nick = m.Nick
			}
			if addr != `` {
				c.Addr = addr
			}
			if m.EKey != `` {
				c.EncPub = m.EKey
			}
			now := time.Now()
			shouldPrint := now.Sub(c.LastPrint) > 60*time.Second
			c.LastSeen = now
			if shouldPrint {
				c.LastPrint = now
			}
			n.contactsMu.Unlock()
			n.maybePersistContactEKey(m.Node, m.EKey)
			n.pendingMu.Lock()
			n.pending[m.Node] = &Contact{Pub: m.Node, Nick: m.Nick, Addr: addr, EncPub: m.EKey, LastSeen: time.Now()}
			n.pendingMu.Unlock()
			if shouldPrint && n.eventHandler != nil {
				n.eventHandler(EventPeerRequest, PeerRequestEvent{Pub: m.Node, Nick: m.Nick, Addr: addr})
			}
		case `PEER_ACK`:
			n.markAcceptedBy(m.Node)
			n.contactsMu.Lock()
			c := n.contacts[m.Node]
			if c != nil && m.EKey != `` {
				c.EncPub = m.EKey
			}
			n.contactsMu.Unlock()
			n.maybePersistContactEKey(m.Node, m.EKey)
			if n.eventHandler != nil {
				n.eventHandler(EventPeerAccepted, m.Node)
			}
		}
	}
}

func (n *Node) dialOnce(addr string) {
	if !strings.Contains(addr, `:`) {
		return
	}
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: n.yggIP, Port: 0, Zone: n.iface}, Timeout: 5 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, `tcp`, addr)
	if err != nil {
		return
	}
	defer conn.Close()

	dec := bufio.NewScanner(conn)
	dec.Buffer(make([]byte, 0, 65536), 2<<20)
	enc := json.NewEncoder(conn)

	if !dec.Scan() {
		return
	}
	var ph WireMsg
	if err := json.Unmarshal(dec.Bytes(), &ph); err != nil {
		return
	}
	if ph.Kind != `HELLO` {
		return
	}
	n.touchContact(ph.Node, ph.Nick, ph.Listen, ph.EKey)

	_ = enc.Encode(WireMsg{Kind: `HELLO`, Node: n.cfg.PubKeyB64, Nick: n.cfg.Nick, Listen: n.cfg.ListenOn, EKey: base64.StdEncoding.EncodeToString(n.encPub[:])})

	if !n.isAcceptedBy(ph.Node) {
		_ = enc.Encode(WireMsg{Kind: `PEER_REQ`, Node: n.cfg.PubKeyB64, Nick: n.cfg.Nick, Listen: n.cfg.ListenOn, EKey: base64.StdEncoding.EncodeToString(n.encPub[:])})
	}

	if !dec.Scan() {
		return
	}
	var have WireMsg
	if err := json.Unmarshal(dec.Bytes(), &have); err != nil {
		return
	}
	if have.Kind != `HAVE` {
		return
	}

	_ = enc.Encode(WireMsg{Kind: `HAVE`, IDs: n.lastIDs(128)})

	missing := n.missingOf(have.IDs)
	if len(missing) > 0 {
		_ = enc.Encode(WireMsg{Kind: `WANT`, IDs: missing})
	}

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	for dec.Scan() {
		var m WireMsg
		if err := json.Unmarshal(dec.Bytes(), &m); err != nil {
			break
		}
		switch m.Kind {
		case `EVENT`:
			if m.Event != nil {
				n.ingestEvent(*m.Event, false)
			}
		case `PEER_ACK`:
			n.markAcceptedBy(m.Node)
		}
	}
}

func (n *Node) dialAndAck(addr string) {
	if addr == `` {
		return
	}
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: n.yggIP, Port: 0, Zone: n.iface}, Timeout: 5 * time.Second}
	conn, err := d.Dial(`tcp`, addr)
	if err != nil {
		return
	}
	defer conn.Close()
	dec := bufio.NewScanner(conn)
	dec.Buffer(make([]byte, 0, 65536), 2<<20)
	enc := json.NewEncoder(conn)

	if !dec.Scan() {
		return
	}
	var ph WireMsg
	if err := json.Unmarshal(dec.Bytes(), &ph); err != nil {
		return
	}
	if ph.Kind != `HELLO` {
		return
	}

	_ = enc.Encode(WireMsg{Kind: `HELLO`, Node: n.cfg.PubKeyB64, Nick: n.cfg.Nick, Listen: n.cfg.ListenOn, EKey: base64.StdEncoding.EncodeToString(n.encPub[:])})
	_ = enc.Encode(WireMsg{Kind: `PEER_ACK`, Node: n.cfg.PubKeyB64, Nick: n.cfg.Nick, Listen: n.cfg.ListenOn, EKey: base64.StdEncoding.EncodeToString(n.encPub[:])})
}

func (n *Node) peerDialLoop() {
	t := time.NewTicker(7 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-n.quit:
			return
		case <-t.C:
			for _, p := range n.ListPeers() {
				go n.dialOnce(p)
			}
		}
	}
}

func (n *Node) touchContact(pub, nick, addr, ekey string) {
	if pub == `` {
		return
	}
	n.contactsMu.Lock()
	c := n.contacts[pub]
	if c == nil {
		c = &Contact{Pub: pub}
		n.contacts[pub] = c
	}
	if nick != `` {
		c.Nick = nick
	}
	if addr != `` {
		c.Addr = addr
	}
	if ekey != `` {
		c.EncPub = ekey
	}
	c.Accepted = n.isAccepted(pub)
	c.LastSeen = time.Now()
	n.contactsMu.Unlock()
	if ekey != `` {
		n.maybePersistContactEKey(pub, ekey)
	}
}

func (n *Node) maybePersistContactEKey(edpub, ekey string) {
	if edpub == `` || ekey == `` {
		return
	}
	n.cfgMu.Lock()
	changed := false
	if n.cfg.ContactEKey == nil {
		n.cfg.ContactEKey = map[string]string{}
		changed = true
	}
	if cur, ok := n.cfg.ContactEKey[edpub]; !ok || cur != ekey {
		n.cfg.ContactEKey[edpub] = ekey
		changed = true
	}
	if changed {
		_ = saveJSONAtomic(n.cfgPath, n.cfg)
	}
	n.cfgMu.Unlock()
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
		return
	}
	n.touchContact(e.Author, e.Nick, ``, ``)
	n.stateMu.Lock()
	if _, ok := n.state.Events[e.ID]; ok {
		n.stateMu.Unlock()
		return
	}
	n.state.Events[e.ID] = e
	n.state.Order = append(n.state.Order, e.ID)
	n.stateMu.Unlock()
	_ = saveJSONAtomic(n.statePath, n.state)

	if n.eventHandler == nil {
		return
	}

	plain, ok := n.decryptEvent(&e)
	switch e.Typ {
	case `msg`:
		n.eventHandler(EventMessage, MessageEvent{
			Timestamp: time.Unix(e.TS, 0),
			Author:    e.Author,
			Nick:      e.Nick,
			Body:      plain,
			Encrypted: !ok,
		})
	case `dm`:
		if e.Author == n.cfg.PubKeyB64 {
			n.eventHandler(EventDM, DMEvent{
				Timestamp: time.Unix(e.TS, 0),
				Author:    e.Author,
				Nick:      e.Nick,
				To:        e.To,
				Body:      plain,
				Encrypted: !ok,
				Incoming:  false,
			})
		} else if e.To == n.cfg.PubKeyB64 {
			if ok {
				n.lastDMFromMu.Lock()
				n.lastDMFrom = e.Author
				n.lastDMFromMu.Unlock()
			}
			n.eventHandler(EventDM, DMEvent{
				Timestamp: time.Unix(e.TS, 0),
				Author:    e.Author,
				Nick:      e.Nick,
				To:        e.To,
				Body:      plain,
				Encrypted: !ok,
				Incoming:  true,
			})
		}
	}
}

// ---------- Event verification ----------

type encDigest struct {
	Scheme string       `json:"scheme"`
	SPK    string       `json:"spk"`
	N      string       `json:"n"`
	CT     string       `json:"ct"`
	Keys   []encKeyItem `json:"keys"`
}

type encKeyItem struct {
	R  string `json:"r"`
	N  string `json:"n"`
	CT string `json:"ct"`
}

func canonicalizeEnc(enc *EncPayload) *encDigest {
	if enc == nil {
		return nil
	}
	out := &encDigest{Scheme: enc.Scheme, SPK: enc.SPK, N: enc.N, CT: enc.CT}
	keys := make([]string, 0, len(enc.Keys))
	for k := range enc.Keys {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		kw := enc.Keys[k]
		out.Keys = append(out.Keys, encKeyItem{R: k, N: kw.N, CT: kw.CT})
	}
	return out
}

func eventDigest(e *Event) []byte {
	type bare struct {
		Typ    string     `json:"type"`
		Author string     `json:"author"`
		Nick   string     `json:"nick"`
		Body   string     `json:"body,omitempty"`
		To     string     `json:"to,omitempty"`
		TS     int64      `json:"ts"`
		Enc    *encDigest `json:"enc,omitempty"`
	}
	var encD *encDigest
	if e.Enc != nil {
		encD = canonicalizeEnc(e.Enc)
	}
	j, _ := json.Marshal(bare{e.Typ, e.Author, e.Nick, e.Body, e.To, e.TS, encD})
	sum := sha256.Sum256(j)
	return sum[:]
}

func signEvent(priv ed25519.PrivateKey, e *Event) {
	d := eventDigest(e)
	id := sha256.Sum256(append([]byte(`id:`), d...))
	e.ID = hex.EncodeToString(id[:])
	e.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, d))
}

func verifyEvent(e *Event) error {
	pub, err := base64.StdEncoding.DecodeString(e.Author)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf(`bad author`)
	}
	sig, err := base64.StdEncoding.DecodeString(e.Sig)
	if err != nil {
		return fmt.Errorf(`bad sig`)
	}
	d := eventDigest(e)
	if !ed25519.Verify(ed25519.PublicKey(pub), d, sig) {
		return errors.New(`signature verify failed`)
	}
	id := sha256.Sum256(append([]byte(`id:`), d...))
	if hex.EncodeToString(id[:]) != e.ID {
		return errors.New(`id mismatch`)
	}
	return nil
}

// ---------- Encryption ----------

func (n *Node) encPubB64() string {
	return base64.StdEncoding.EncodeToString(n.encPub[:])
}

func (n *Node) getEncPubFor(edPub string) (string, bool) {
	n.contactsMu.Lock()
	c := n.contacts[edPub]
	n.contactsMu.Unlock()
	if c != nil && c.EncPub != `` {
		return c.EncPub, true
	}
	n.cfgMu.Lock()
	e, ok := n.cfg.ContactEKey[edPub]
	n.cfgMu.Unlock()
	if ok && e != `` {
		return e, true
	}
	return ``, false
}

func (n *Node) encryptForRecipients(plaintext []byte, recipients map[string]string) (*EncPayload, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	bodyNonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(bodyNonce); err != nil {
		return nil, err
	}
	cipher, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	ct := cipher.Seal(nil, bodyNonce, plaintext, nil)

	keys := make(map[string]KeyWrap, len(recipients))
	for recEd, recEncB64 := range recipients {
		recEnc, err := decodeB64To32(recEncB64)
		if err != nil {
			continue
		}
		wrapNonce := make([]byte, 24)
		if _, err := rand.Read(wrapNonce); err != nil {
			return nil, err
		}
		var nArr [24]byte
		copy(nArr[:], wrapNonce)
		sealed := box.Seal(nil, key, &nArr, recEnc, n.encPriv)
		keys[recEd] = KeyWrap{N: base64.StdEncoding.EncodeToString(wrapNonce), CT: base64.StdEncoding.EncodeToString(sealed)}
	}

	return &EncPayload{
		Scheme: `xchacha20poly1305+box`,
		SPK:    n.encPubB64(),
		N:      base64.StdEncoding.EncodeToString(bodyNonce),
		CT:     base64.StdEncoding.EncodeToString(ct),
		Keys:   keys,
	}, nil
}

func (n *Node) decryptEvent(e *Event) (string, bool) {
	if e.Enc == nil {
		return e.Body, e.Body != ``
	}
	kw, ok := e.Enc.Keys[n.cfg.PubKeyB64]
	if !ok {
		return ``, false
	}
	spk, err := decodeB64To32(e.Enc.SPK)
	if err != nil {
		return ``, false
	}
	wb, err := base64.StdEncoding.DecodeString(kw.CT)
	if err != nil {
		return ``, false
	}
	nb, err := base64.StdEncoding.DecodeString(kw.N)
	if err != nil || len(nb) != 24 {
		return ``, false
	}
	var nArr [24]byte
	copy(nArr[:], nb)
	key, ok2 := box.Open(nil, wb, &nArr, spk, n.encPriv)
	if !ok2 {
		return ``, false
	}
	nonce, err := base64.StdEncoding.DecodeString(e.Enc.N)
	if err != nil || len(nonce) != chacha20poly1305.NonceSizeX {
		return ``, false
	}
	ct, err := base64.StdEncoding.DecodeString(e.Enc.CT)
	if err != nil {
		return ``, false
	}
	cipher, err := chacha20poly1305.NewX(key)
	if err != nil {
		return ``, false
	}
	pt, err := cipher.Open(nil, nonce, ct, nil)
	if err != nil {
		return ``, false
	}
	return string(pt), true
}

func (n *Node) recipientsForGlobal() map[string]string {
	recip := map[string]string{}
	recip[n.cfg.PubKeyB64] = n.encPubB64()
	n.cfgMu.Lock()
	acceptedCopy := make(map[string]bool, len(n.cfg.Accepted))
	for edpub, ok := range n.cfg.Accepted {
		acceptedCopy[edpub] = ok
	}
	n.cfgMu.Unlock()
	for edpub, ok := range acceptedCopy {
		if !ok {
			continue
		}
		if encPub, ok2 := n.getEncPubFor(edpub); ok2 {
			recip[edpub] = encPub
		}
	}
	return recip
}
