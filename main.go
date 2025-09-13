// gossipy.go (E2E fan-out encrypted)
// Global gossip + DMs, QR share links, and a *mutual* handshake.
// NOW WITH APP-LAYER ENCRYPTION:
//   - Global messages ("everyone") and DMs are encrypted at the application layer.
//   - For each message, a random symmetric key encrypts the body once.
//   - That symmetric key is then *individually wrapped* (nacl/box) to the
//     X25519 public keys of the peers you had accepted at send time + yourself.
//   - New peers added later cannot decrypt old messages.
//
// Transport still uses Yggdrasil (encrypted), but app E2E is now enabled.
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
// Plain typing => global chat (app-layer E2E).

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
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/nacl/box"
)

const version = "0.3.1"

// ---------- Config & State ----------

type Config struct {
	Nick        string            `json:"nick"`
	PrivKeyB64  string            `json:"privkey"`
	PubKeyB64   string            `json:"pubkey"`
	EncPrivB64  string            `json:"enc_privkey"` // X25519 enc key (nacl/box)
	EncPubB64   string            `json:"enc_pubkey"`
	Peers       []string          `json:"peers"`         // [ipv6]:port
	ListenOn    string            `json:"listen_on"`     // info
	Accepted    map[string]bool   `json:"accepted"`      // ed25519 pub -> we've accepted them
	ContactEKey map[string]string `json:"contact_ekeys"` // ed25519 pub -> their X25519 pub (persisted)
}

type KeyWrap struct {
	N  string `json:"n"`  // 24-byte nonce (base64)
	CT string `json:"ct"` // ciphertext (base64)
}

type EncPayload struct {
	Scheme string             `json:"scheme"` // "xchacha20poly1305+box"
	SPK    string             `json:"spk"`    // sender X25519 pub (base64)
	N      string             `json:"n"`      // body nonce (base64, 24 bytes)
	CT     string             `json:"ct"`     // encrypted body (base64)
	Keys   map[string]KeyWrap `json:"keys"`   // recipient Ed25519 pub -> keywrap
}

type Event struct {
	ID     string      `json:"id"`
	Typ    string      `json:"type"`   // "msg" or "dm"
	Author string      `json:"author"` // base64 Ed25519 pub
	Nick   string      `json:"nick"`
	Body   string      `json:"body,omitempty"` // legacy plaintext (unused when enc present)
	Enc    *EncPayload `json:"enc,omitempty"`  // encrypted payload
	To     string      `json:"to,omitempty"`
	TS     int64       `json:"ts"`
	Sig    string      `json:"sig"`
}

type State struct {
	Events map[string]Event `json:"events"`
	Order  []string         `json:"order"`
}

// Wire messages
// EKey carries X25519 encryption pubkey for nacl/box.
type WireMsg struct {
	Kind   string   `json:"kind"`           // "HELLO","HAVE","WANT","EVENT","PEER_REQ","PEER_ACK"
	Node   string   `json:"node,omitempty"` // base64 Ed25519 pub
	Nick   string   `json:"nick,omitempty"`
	Listen string   `json:"listen,omitempty"` // "[ipv6]:port"
	EKey   string   `json:"ekey,omitempty"`   // base64 X25519 pub
	IDs    []string `json:"ids,omitempty"`
	Event  *Event   `json:"event,omitempty"`
}

// Contact info
type Contact struct {
	Pub       string
	Nick      string
	Addr      string
	EncPub    string // X25519 pub (base64)
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

	encPriv *[32]byte // X25519 private (nacl/box)
	encPub  *[32]byte // X25519 public

	peersMu sync.Mutex
	peers   map[string]struct{} // addresses we dial

	contactsMu sync.Mutex
	contacts   map[string]*Contact // ed25519 pub -> contact

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
		// Backfill enc keys if missing
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
		_ = saveJSONAtomic(path, &c) // persist any backfill
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

func last4(ip net.IP) string {
	if ip == nil {
		return `????`
	}
	b := ip.To16()
	if b == nil {
		return `????`
	}
	he := uint16(b[14])<<8 | uint16(b[15])
	return strings.ToLower(fmt.Sprintf(`%04x`, he))
}

func last4FromIPv6String(bracketAddr string) string {
	host := bracketAddr
	if i := strings.LastIndex(host, `]`); i >= 0 {
		host = host[:i+1]
	}
	host = strings.Trim(host, `[]`)
	ip := net.ParseIP(host)
	if ip == nil {
		return `????`
	}
	return last4(ip)
}

func shortKey(b64 string) string {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(b) < 3 {
		return `BADKEY`
	}
	return strings.ToUpper(hex.EncodeToString(b[:3]))
}

// ---------- Events ----------

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
	out := &encDigest{Scheme: enc.Scheme, SPK: enc.SPK, N: enc.N, CT: encCT(enc)}
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

func encCT(enc *EncPayload) string { return enc.CT }

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

// ---------- Node helpers ----------

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
	// Pre-seed contact encryption pubs from persisted map so we can encrypt while offline
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
	ln, err := net.ListenTCP(`tcp6`, laddr)
	if err != nil {
		return fmt.Errorf(`listen on %s: %w`, laddr.String(), err)
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
			fmt.Println(`[ERR] accept:`, err)
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

	// Send HELLO (with enc pub)
	if err := enc.Encode(WireMsg{Kind: `HELLO`, Node: n.cfg.PubKeyB64, Nick: n.cfg.Nick, Listen: n.cfg.ListenOn, EKey: base64.StdEncoding.EncodeToString(n.encPub[:])}); err != nil {
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
	if peerHello.Kind != `HELLO` {
		return
	}
	n.touchContact(peerHello.Node, peerHello.Nick, peerHello.Listen, peerHello.EKey)

	// Send HAVE (always send)
	if err := enc.Encode(WireMsg{Kind: `HAVE`, IDs: n.lastIDs(128)}); err != nil {
		return
	}

	for {
		if !dec.Scan() {
			if err := dec.Err(); err != nil && err != io.EOF {
				fmt.Println(`[peer read]`, err)
			}
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
			if shouldPrint {
				fmt.Printf("[request] %s (%s) asks to peer: %s — /accept %s\n", n.prettyContact(c), shortKey(m.Node), displayAddr(addr), shortKey(m.Node))
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

	// Read server HELLO
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

	// Send HELLO (+ our enc pub)
	_ = enc.Encode(WireMsg{Kind: `HELLO`, Node: n.cfg.PubKeyB64, Nick: n.cfg.Nick, Listen: n.cfg.ListenOn, EKey: base64.StdEncoding.EncodeToString(n.encPub[:])})

	// IMPORTANT: send PEER_REQ until they PEER_ACK us (mutual handshake)
	if !n.isAcceptedBy(ph.Node) {
		_ = enc.Encode(WireMsg{Kind: `PEER_REQ`, Node: n.cfg.PubKeyB64, Nick: n.cfg.Nick, Listen: n.cfg.ListenOn, EKey: base64.StdEncoding.EncodeToString(n.encPub[:])})
	}

	// Read HAVE
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

	// Send HAVE (client also advertises)
	_ = enc.Encode(WireMsg{Kind: `HAVE`, IDs: n.lastIDs(128)})

	// Send WANT
	missing := n.missingOf(have.IDs)
	if len(missing) > 0 {
		_ = enc.Encode(WireMsg{Kind: `WANT`, IDs: missing})
	}

	// Receive EVENTS/ACKs briefly
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

// One-shot dial just to deliver a PEER_ACK after /accept (best effort).
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

	// Read server HELLO
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

	// Send HELLO + PEER_ACK
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
			for _, p := range n.listPeers() {
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

func (n *Node) prettyContact(c *Contact) string {
	lf := `????`
	if c.Addr != `` {
		lf = last4FromIPv6String(c.Addr)
	}
	nk := c.Nick
	if nk == `` {
		nk = `anon`
	}
	return fmt.Sprintf(`%s@%s`, nk, lf)
}

func displayAddr(addr string) string {
	if addr == `` {
		return `(no-addr)`
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
		fmt.Println(`[WARN] drop bad event:`, err)
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

	plain, ok := n.decryptEvent(&e)
	switch e.Typ {
	case `msg`:
		if ok {
			fmt.Printf("[%s][global] %s: %s\n", time.Unix(e.TS, 0).Format(`15:04:05`), displayFrom(e.Nick, e.Author), plain)
		} else {
			fmt.Printf("[%s][global] %s: [encrypted—no access]\n", time.Unix(e.TS, 0).Format(`15:04:05`), displayFrom(e.Nick, e.Author))
		}
	case `dm`:
		if e.Author == n.cfg.PubKeyB64 {
			if ok {
				fmt.Printf("[%s] ✉️ to %s: %s\n", time.Unix(e.TS, 0).Format(`15:04:05`), targetLabel(n, e.To), plain)
			} else {
				fmt.Printf("[%s] ✉️ to %s: [encrypted]\n", time.Unix(e.TS, 0).Format(`15:04:05`), targetLabel(n, e.To))
			}
		} else if e.To == n.cfg.PubKeyB64 {
			if ok {
				fmt.Printf("[%s] ✉️ from %s: %s\n", time.Unix(e.TS, 0).Format(`15:04:05`), displayFrom(e.Nick, e.Author), plain)
				n.lastDMFromMu.Lock()
				n.lastDMFrom = e.Author
				n.lastDMFromMu.Unlock()
			} else {
				fmt.Printf("[%s] ✉️ from %s: [encrypted—cannot decrypt]\n", time.Unix(e.TS, 0).Format(`15:04:05`), displayFrom(e.Nick, e.Author))
			}
		}
	}
}

func displayFrom(nick, authorB64 string) string {
	b, err := base64.StdEncoding.DecodeString(authorB64)
	if err != nil || len(b) < 3 {
		if nick == `` {
			nick = `anon`
		}
		return fmt.Sprintf(`%s~BADKEY`, nick)
	}
	hexid := strings.ToUpper(hex.EncodeToString(b[:3]))
	if nick == `` {
		nick = `anon`
	}
	return fmt.Sprintf(`%s~%s`, nick, hexid)
}

func targetLabel(n *Node, toB64 string) string {
	n.contactsMu.Lock()
	defer n.contactsMu.Unlock()
	if c := n.contacts[toB64]; c != nil && c.Nick != `` {
		return fmt.Sprintf(`%s~%s`, c.Nick, shortKey(toB64))
	}
	return `~` + shortKey(toB64)
}

// ---------- Encryption helpers ----------

func (n *Node) encPubB64() string { return base64.StdEncoding.EncodeToString(n.encPub[:]) }

func (n *Node) getEncPubFor(edPub string) (string, bool) {
	// first, contact map
	n.contactsMu.Lock()
	c := n.contacts[edPub]
	n.contactsMu.Unlock()
	if c != nil && c.EncPub != `` {
		return c.EncPub, true
	}
	// fallback to persisted cache
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

// ---------- Send helpers ----------

func (n *Node) recipientsForGlobal() map[string]string {
	recip := map[string]string{}
	// include self to be able to read our own messages later
	recip[n.cfg.PubKeyB64] = n.encPubB64()
	// all accepted peers with known enc pub (from memory or persisted cache)
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

func (n *Node) sendGlobal(body string) {
	recip := n.recipientsForGlobal()
	enc, err := n.encryptForRecipients([]byte(body), recip)
	if err != nil {
		fmt.Println(`[ERR] encrypt global:`, err)
		return
	}
	ev := &Event{Typ: `msg`, Author: n.cfg.PubKeyB64, Nick: n.cfg.Nick, Enc: enc, TS: time.Now().Unix()}
	signEvent(n.priv, ev)
	n.ingestEvent(*ev, true)
}

func (n *Node) sendDM(targetPubB64, body string) {
	recip := map[string]string{n.cfg.PubKeyB64: n.encPubB64()}
	if encPub, ok := n.getEncPubFor(targetPubB64); ok {
		recip[targetPubB64] = encPub
	} else {
		fmt.Println(`[err] recipient has no encryption key yet; try after they connect once`)
		return
	}
	enc, err := n.encryptForRecipients([]byte(body), recip)
	if err != nil {
		fmt.Println(`[ERR] encrypt dm:`, err)
		return
	}
	ev := &Event{Typ: `dm`, Author: n.cfg.PubKeyB64, Nick: n.cfg.Nick, To: targetPubB64, Enc: enc, TS: time.Now().Unix()}
	signEvent(n.priv, ev)
	n.ingestEvent(*ev, true)
}

// ---------- Links & QR ----------

func (n *Node) buildLink() string {
	u := &url.URL{Scheme: `gossipy`, Host: fmt.Sprintf(`[%s]:%d`, n.yggIP.String(), n.port)}
	q := url.Values{}
	q.Set(`id`, base64.RawURLEncoding.EncodeToString(n.pub))
	q.Set(`nick`, n.cfg.Nick)
	u.RawQuery = q.Encode()
	return u.String()
}

func (n *Node) showLinkQR() {
	link := n.buildLink()
	fmt.Println(`Share this link (or QR) so friends can connect & send you a peer request:`)
	fmt.Println(link, `
`)
	qrterminal.GenerateWithConfig(link, qrterminal.Config{Level: qrterminal.M, Writer: os.Stdout, BlackChar: qrterminal.BLACK, WhiteChar: qrterminal.WHITE, QuietZone: 1})
	fmt.Println()
}

func parseLink(s string) (addr, pubB64, nick string, err error) {
	if !strings.HasPrefix(s, `gossipy://`) {
		return ``, ``, ``, errors.New(`not a gossipy:// link`)
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

// ---------- REPL ----------

func (n *Node) repl() {
	in := bufio.NewReader(os.Stdin)
	fmt.Printf(`Type text to chat [global]. Use /help for commands.\n`)
	for {
		fmt.Printf(`[%s@%s] > `, n.cfg.Nick, last4(n.yggIP))
		line, err := in.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				fmt.Println()
				close(n.quit)
				return
			}
			fmt.Println(`[read err]`, err)
			continue
		}
		line = strings.TrimSpace(line)
		if line == `` {
			continue
		}
		if strings.HasPrefix(line, `/`) {
			n.handleCommand(line)
			continue
		}
		n.sendGlobal(line)
	}
}

func (n *Node) handleCommand(line string) {
	parts := strings.Fields(line)
	cmd := strings.ToLower(strings.TrimPrefix(parts[0], `/`))
	switch cmd {
	case `help`:
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
	case `link`:
		n.showLinkQR()
	case `pending`:
		n.pendingMu.Lock()
		if len(n.pending) == 0 {
			fmt.Println(`(no pending requests)`)
		}
		for pub, c := range n.pending {
			fmt.Printf(" - %s (%s) addr=%s seen=%s\n", displayFrom(c.Nick, pub), shortKey(pub), displayAddr(c.Addr), c.LastSeen.Format(`15:04:05`))
		}
		n.pendingMu.Unlock()
	case `contacts`:
		n.contactsMu.Lock()
		if len(n.contacts) == 0 {
			fmt.Println(`(no contacts yet)`)
		} else {
			keys := make([]string, 0, len(n.contacts))
			for k := range n.contacts {
				keys = append(keys, k)
			}
			sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
			for _, pub := range keys {
				c := n.contacts[pub]
				acc := `no`
				if c.Accepted {
					acc = `yes`
				}
				enc := `noekey`
				if c.EncPub != `` {
					enc = `ekey`
				}
				fmt.Printf(" - %s (%s) addr=%s accepted=%s enc=%s\n", displayFrom(c.Nick, pub), shortKey(pub), displayAddr(c.Addr), acc, enc)
			}
		}
		n.contactsMu.Unlock()
	case `accept`:
		if len(parts) < 2 {
			fmt.Println(`usage: /accept <gossipy://... | pubkey | SHORTID>`)
			return
		}
		arg := strings.TrimSpace(strings.TrimPrefix(line, `/accept`))
		if strings.HasPrefix(arg, `gossipy://`) {
			addr, pub, nick, err := parseLink(arg)
			if err != nil {
				fmt.Println(`[err]`, err)
				return
			}
			n.addPeer(addr)
			if pub != `` {
				n.markAccepted(pub, addr, nick)
				fmt.Printf("[ok] added peer %s and accepted %s (%s)\n", displayAddr(addr), nickOrShort(pub, nick), shortKey(pub))
				go n.dialAndAck(addr)
			} else {
				fmt.Printf("[ok] added peer %s\n", displayAddr(addr))
			}
			return
		}
		targetPub := n.resolveByPubOrShort(arg)
		if targetPub == `` {
			n.pendingMu.Lock()
			if _, ok := n.pending[arg]; ok {
				targetPub = arg
			}
			n.pendingMu.Unlock()
		}
		if targetPub == `` {
			fmt.Println(`[err] no pending or known contact:`, arg)
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
		fmt.Printf("[ok] accepted %s (%s)%s\n", nickOrShort(targetPub, nick), shortKey(targetPub), optionalAddr(addr))
	case `unpeer`:
		if len(parts) < 2 {
			fmt.Println(`usage: /unpeer <pub|SHORTID>`)
			return
		}
		pub := n.resolveByPubOrShort(parts[1])
		if pub == `` {
			fmt.Println(`[err] unknown contact`)
			return
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
		fmt.Printf("[ok] unpeered %s (%s)\n", nickOrShort(pub, ``), shortKey(pub))
	case `peers`:
		for _, p := range n.listPeers() {
			fmt.Println(` -`, p)
		}
	case `nick`:
		if len(parts) < 2 {
			fmt.Println(`usage: /nick <name>`)
			return
		}
		newNick := strings.TrimSpace(strings.TrimPrefix(line, `/nick`))
		n.cfgMu.Lock()
		n.cfg.Nick = newNick
		_ = saveJSONAtomic(n.cfgPath, n.cfg)
		n.cfgMu.Unlock()
		fmt.Println(`[ok] nick set`)
	case `msg`:
		if len(parts) < 3 {
			fmt.Println(`usage: /msg <who> <text>`)
			return
		}
		who := parts[1]
		text := strings.TrimSpace(strings.TrimPrefix(line, `/msg`))
		if i := strings.Index(text, who); i >= 0 {
			text = strings.TrimSpace(text[i+len(who):])
		}
		pub := n.resolveWho(who)
		if pub == `` {
			fmt.Println(`[err] unknown recipient:`, who)
			return
		}
		n.sendDM(pub, text)
	case `r`:
		if len(parts) < 2 {
			fmt.Println(`usage: /r <text>`)
			return
		}
		n.lastDMFromMu.Lock()
		target := n.lastDMFrom
		n.lastDMFromMu.Unlock()
		if target == `` {
			fmt.Println(`[err] no recent *incoming* DM. Use /msg <who> <text>.`)
			return
		}
		text := strings.TrimSpace(strings.TrimPrefix(line, `/r`))
		n.sendDM(target, text)
	case `save`:
		_ = saveJSONAtomic(n.statePath, n.state)
		fmt.Println(`[ok] saved`)
	case `quit`, `exit`:
		close(n.quit)
	default:
		fmt.Println(`unknown command. /help for help`)
	}
}

func (n *Node) resolveByPubOrShort(s string) string {
	if strings.Contains(s, `=`) && len(s) > 40 {
		return s
	}
	n.contactsMu.Lock()
	defer n.contactsMu.Unlock()
	for pub := range n.contacts {
		if strings.EqualFold(shortKey(pub), s) {
			return pub
		}
	}
	return ``
}

func (n *Node) resolveWho(who string) string {
	if strings.Contains(who, `=`) && len(who) > 40 {
		return who
	}
	n.contactsMu.Lock()
	defer n.contactsMu.Unlock()
	for pub, c := range n.contacts {
		if strings.EqualFold(shortKey(pub), who) || (c.Nick != `` && strings.EqualFold(c.Nick, who)) {
			return pub
		}
	}
	return ``
}

// ---------- main ----------

func main() {
	var (
		iface = flag.String(`iface`, `tun0`, `Yggdrasil interface (e.g. tun0 or ygg0)`)
		port  = flag.Int(`port`, 19999, `TCP port to listen on (IPv6)`)
		state = flag.String(`state`, `./gossipy_state.json`, `Path to state JSON`)
		conf  = flag.String(`config`, `./gossipy_config.json`, `Path to config JSON`)
		nick  = flag.String(`nick`, ``, `Nickname (optional)`)
		peer  = flag.String(`peer`, ``, `Add a peer on startup ([IPv6]:port)`)
	)
	flag.Parse()

	node, err := NewNode(*conf, *state, *iface, *port, *nick)
	if err != nil {
		fmt.Println(`init error:`, err)
		os.Exit(1)
	}
	if *peer != `` {
		node.addPeer(*peer)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	go func() {
		if err := node.listenAndServe(); err != nil {
			fmt.Println(`server error:`, err)
			close(node.quit)
		}
	}()

	fmt.Printf("gossipy v%s | nick=%q | id=%s\n", version, node.cfg.Nick, shortKey(node.cfg.PubKeyB64))
	fmt.Printf("Address: [%s]:%d (iface=%s)\n", node.yggIP.String(), node.port, node.iface)
	fmt.Printf("Peers: %v\n", node.listPeers())
	fmt.Println(`Tip: /link to print a QR; /accept <gossipy://…> to connect; /pending then /accept <SHORTID> to approve.`)

	go node.repl()

	select {
	case <-ctx.Done():
	case <-node.quit:
	}
	fmt.Println(`
shutting down...`)
}

// ---------- small format helpers ----------

func nickOrShort(pub, nick string) string {
	if nick != `` {
		return nick
	}
	return `~` + shortKey(pub)
}
func optionalAddr(addr string) string {
	if addr == `` {
		return ``
	}
	return ` and added peer ` + addr
}
