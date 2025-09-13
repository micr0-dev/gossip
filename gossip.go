package main

import (
	"bufio"
	"bytes"
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

const Version = "0.4.1"
const MaxFileSize = 100 * 1024 * 1024 // 100MB max
const ChunkSize = 64 * 1024           // 64KB chunks

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
	ID       string      `json:"id"`
	Typ      string      `json:"type"` // "msg", "dm", "file_announce", "file_request", "chunk"
	Author   string      `json:"author"`
	Nick     string      `json:"nick"`
	Body     string      `json:"body,omitempty"`
	Enc      *EncPayload `json:"enc,omitempty"`
	To       string      `json:"to,omitempty"`
	TS       int64       `json:"ts"`
	Sig      string      `json:"sig"`
	FileMeta *FileMeta   `json:"file_meta,omitempty"`
	FileReq  *FileReq    `json:"file_req,omitempty"`
	ChunkRef *ChunkRef   `json:"chunk_ref,omitempty"`
}

type FileMeta struct {
	FileID     string `json:"file_id"`
	Name       string `json:"name"`
	Size       int64  `json:"size"`
	Hash       string `json:"hash"`
	MimeType   string `json:"mime_type"`
	ChunkCount int    `json:"chunk_count"`
}

type FileReq struct {
	FileID    string `json:"file_id"`
	Requester string `json:"requester"`
}

type ChunkRef struct {
	FileID    string `json:"file_id"`
	Index     int    `json:"index"`
	Hash      string `json:"hash"`
	Data      string `json:"data"`                // base64 encoded chunk
	Requester string `json:"requester,omitempty"` // who requested this chunk
}

type State struct {
	Events map[string]Event `json:"events"`
	Order  []string         `json:"order"`
}

type FileOffer struct {
	Meta      *FileMeta
	LocalPath string // path to the actual file (for sharing)
	From      string // who's offering
	Nick      string
	OfferTime time.Time
	IsLocal   bool // true if we're offering this file
}

type FileDownload struct {
	Meta           *FileMeta
	ReceivedChunks map[int][]byte
	RequestTime    time.Time
	From           string
	Complete       bool
	SavePath       string
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
	EventFileOffer
	EventFileProgress
	EventFileComplete
)

type MessageEvent struct {
	Event     *Event
	Timestamp time.Time
	Author    string
	Nick      string
	Body      string
	Encrypted bool
}

type DMEvent struct {
	Event     *Event
	Timestamp time.Time
	Author    string
	Nick      string
	To        string
	Body      string
	Encrypted bool
	Incoming  bool
}

type PeerRequestEvent struct {
	Pub  string
	Nick string
	Addr string
}

type FileOfferEvent struct {
	FileID   string
	FileName string
	FileSize int64
	From     string
	Nick     string
}

type FileProgressEvent struct {
	FileID         string
	FileName       string
	ReceivedChunks int
	TotalChunks    int
	Percent        float64
}

type FileCompleteEvent struct {
	FileID   string
	FileName string
	SavePath string
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

	fileOffersMu sync.Mutex
	fileOffers   map[string]*FileOffer // Available files

	fileDownloadsMu sync.Mutex
	fileDownloads   map[string]*FileDownload // Files we're downloading

	downloadDir string

	quit         chan struct{}
	eventHandler EventHandler
}

type EventHandler func(EventType, interface{})

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

	downloadDir := filepath.Join(filepath.Dir(statePath), "downloads")
	os.MkdirAll(downloadDir, 0755)

	n := &Node{
		cfgPath:       cfgPath,
		cfg:           cfg,
		statePath:     statePath,
		state:         st,
		iface:         iface,
		yggIP:         yip,
		port:          port,
		priv:          priv,
		pub:           pub,
		encPriv:       encPriv,
		encPub:        encPub,
		peers:         map[string]struct{}{},
		contacts:      map[string]*Contact{},
		pending:       map[string]*Contact{},
		acceptedBy:    map[string]bool{},
		fileOffers:    map[string]*FileOffer{},
		fileDownloads: map[string]*FileDownload{},
		downloadDir:   downloadDir,
		quit:          make(chan struct{}),
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

// ---------- Search & History API ----------

func (n *Node) SearchMessages(query string, limit int) []Event {
	n.stateMu.Lock()
	defer n.stateMu.Unlock()

	query = strings.ToLower(query)
	results := []Event{}

	for i := len(n.state.Order) - 1; i >= 0 && len(results) < limit; i-- {
		e := n.state.Events[n.state.Order[i]]
		if e.Typ != "msg" && e.Typ != "dm" {
			continue
		}

		plain, ok := n.decryptEvent(&e)
		if ok && strings.Contains(strings.ToLower(plain), query) {
			results = append(results, e)
			continue
		}

		if strings.Contains(strings.ToLower(e.Nick), query) {
			results = append(results, e)
		}
	}

	return results
}

func (n *Node) GetMessageHistory(before time.Time, limit int) []Event {
	n.stateMu.Lock()
	defer n.stateMu.Unlock()

	results := []Event{}
	beforeUnix := before.Unix()

	for i := len(n.state.Order) - 1; i >= 0 && len(results) < limit; i-- {
		e := n.state.Events[n.state.Order[i]]
		if e.Typ != "msg" || e.TS >= beforeUnix {
			continue
		}
		results = append(results, e)
	}

	return results
}

func (n *Node) GetDMHistory(withPub string, limit int) []Event {
	n.stateMu.Lock()
	defer n.stateMu.Unlock()

	results := []Event{}

	for i := len(n.state.Order) - 1; i >= 0 && len(results) < limit; i-- {
		e := n.state.Events[n.state.Order[i]]
		if e.Typ != "dm" {
			continue
		}

		if e.Author == withPub || e.To == withPub {
			results = append(results, e)
		}
	}

	return results
}

// ---------- File Sharing API ----------

func (n *Node) ShareFile(filePath string, toPub string) error {
	// Check file exists and size
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("file not found: %w", err)
	}
	if info.Size() > MaxFileSize {
		return fmt.Errorf("file too large: %d bytes (max %d)", info.Size(), MaxFileSize)
	}

	// Read file to calculate hash
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	// Calculate file hash
	fileHash := sha256.Sum256(fileData)
	fileID := hex.EncodeToString(fileHash[:16])

	// Determine MIME type
	mimeType := "application/octet-stream"
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".txt", ".md":
		mimeType = "text/plain"
	case ".jpg", ".jpeg":
		mimeType = "image/jpeg"
	case ".png":
		mimeType = "image/png"
	case ".gif":
		mimeType = "image/gif"
	case ".pdf":
		mimeType = "application/pdf"
	case ".webp":
		mimeType = "image/webp"
	}

	// Calculate chunks
	chunkCount := (len(fileData) + ChunkSize - 1) / ChunkSize

	// Create file metadata
	fileMeta := &FileMeta{
		FileID:     fileID,
		Name:       filepath.Base(filePath),
		Size:       info.Size(),
		Hash:       hex.EncodeToString(fileHash[:]),
		MimeType:   mimeType,
		ChunkCount: chunkCount,
	}

	// Store the file offer locally
	n.fileOffersMu.Lock()
	n.fileOffers[fileID] = &FileOffer{
		Meta:      fileMeta,
		LocalPath: filePath,
		From:      n.cfg.PubKeyB64,
		Nick:      n.cfg.Nick,
		OfferTime: time.Now(),
		IsLocal:   true,
	}
	n.fileOffersMu.Unlock()

	// Create and send file announcement
	var ev *Event
	if toPub == "" {
		ev = &Event{
			Typ:      "file_announce",
			Author:   n.cfg.PubKeyB64,
			Nick:     n.cfg.Nick,
			FileMeta: fileMeta,
			TS:       time.Now().Unix(),
		}
	} else {
		ev = &Event{
			Typ:      "file_announce",
			Author:   n.cfg.PubKeyB64,
			Nick:     n.cfg.Nick,
			To:       toPub,
			FileMeta: fileMeta,
			TS:       time.Now().Unix(),
		}
	}

	signEvent(n.priv, ev)
	n.ingestEvent(*ev, true)

	return nil
}

func (n *Node) GetAvailableFiles() []*FileOffer {
	n.fileOffersMu.Lock()
	defer n.fileOffersMu.Unlock()

	var offers []*FileOffer
	for _, offer := range n.fileOffers {
		offers = append(offers, offer)
	}

	sort.Slice(offers, func(i, j int) bool {
		return offers[i].OfferTime.After(offers[j].OfferTime)
	})

	return offers
}

func (n *Node) GetDownloads() []*FileDownload {
	n.fileDownloadsMu.Lock()
	defer n.fileDownloadsMu.Unlock()

	var downloads []*FileDownload
	for _, dl := range n.fileDownloads {
		downloads = append(downloads, dl)
	}

	return downloads
}

func (n *Node) RequestFile(fileID string) error {
	// Check if file is available
	n.fileOffersMu.Lock()
	offer, ok := n.fileOffers[fileID]
	if !ok {
		n.fileOffersMu.Unlock()
		return fmt.Errorf("file not available: %s", fileID)
	}
	offerCopy := *offer
	n.fileOffersMu.Unlock()

	// Don't download our own files
	if offerCopy.IsLocal {
		return fmt.Errorf("cannot download your own file")
	}

	// Check if already downloading
	n.fileDownloadsMu.Lock()
	if _, downloading := n.fileDownloads[fileID]; downloading {
		n.fileDownloadsMu.Unlock()
		return fmt.Errorf("already downloading this file")
	}

	// Start download tracking
	n.fileDownloads[fileID] = &FileDownload{
		Meta:           offerCopy.Meta,
		ReceivedChunks: make(map[int][]byte),
		RequestTime:    time.Now(),
		From:           offerCopy.From,
		Complete:       false,
	}
	n.fileDownloadsMu.Unlock()

	// Send file request event
	req := &Event{
		Typ:    "file_request",
		Author: n.cfg.PubKeyB64,
		Nick:   n.cfg.Nick,
		FileReq: &FileReq{
			FileID:    fileID,
			Requester: n.cfg.PubKeyB64,
		},
		TS: time.Now().Unix(),
	}

	signEvent(n.priv, req)
	n.ingestEvent(*req, true)

	return nil
}

func (n *Node) SaveDownloadedFile(fileID string, destPath string) error {
	n.fileDownloadsMu.Lock()
	dl, ok := n.fileDownloads[fileID]
	if !ok {
		n.fileDownloadsMu.Unlock()
		return fmt.Errorf("download not found")
	}

	if !dl.Complete {
		n.fileDownloadsMu.Unlock()
		return fmt.Errorf("download not complete")
	}
	n.fileDownloadsMu.Unlock()

	// Reassemble file
	var buf bytes.Buffer
	for i := 0; i < dl.Meta.ChunkCount; i++ {
		chunk, ok := dl.ReceivedChunks[i]
		if !ok {
			return fmt.Errorf("missing chunk %d", i)
		}
		buf.Write(chunk)
	}

	// Verify hash
	fileData := buf.Bytes()
	hash := sha256.Sum256(fileData)
	if hex.EncodeToString(hash[:]) != dl.Meta.Hash {
		return fmt.Errorf("file hash mismatch")
	}

	// Save to disk
	if destPath == "" {
		destPath = filepath.Join(n.downloadDir, dl.Meta.Name)
	}

	if err := os.WriteFile(destPath, fileData, 0644); err != nil {
		return fmt.Errorf("save file: %w", err)
	}

	dl.SavePath = destPath

	return nil
}

// ---------- Core API (from previous version) ----------

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
	return n.persistState()
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

// Helper to send chunks when someone requests a file
func (n *Node) sendFileChunks(fileID string, requester string) {
	n.fileOffersMu.Lock()
	offer, ok := n.fileOffers[fileID]
	if !ok || !offer.IsLocal {
		n.fileOffersMu.Unlock()
		return
	}
	localPath := offer.LocalPath
	meta := offer.Meta
	n.fileOffersMu.Unlock()

	// Read file
	fileData, err := os.ReadFile(localPath)
	if err != nil {
		return
	}

	// Send chunks
	for i := 0; i < meta.ChunkCount; i++ {
		start := i * ChunkSize
		end := start + ChunkSize
		if end > len(fileData) {
			end = len(fileData)
		}

		chunk := fileData[start:end]
		chunkHash := sha256.Sum256(chunk)

		// Create chunk event for the requester
		chunkRef := &ChunkRef{
			FileID:    fileID,
			Index:     i,
			Hash:      hex.EncodeToString(chunkHash[:]),
			Data:      base64.StdEncoding.EncodeToString(chunk),
			Requester: requester,
		}

		ev := &Event{
			Typ:      "chunk",
			Author:   n.cfg.PubKeyB64,
			Nick:     n.cfg.Nick,
			ChunkRef: chunkRef,
			TS:       time.Now().Unix(),
		}

		signEvent(n.priv, ev)
		n.ingestEvent(*ev, true)

		// Small delay between chunks to avoid flooding
		time.Sleep(10 * time.Millisecond)
	}
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

func (n *Node) persistState() error {
	return saveJSONAtomic(n.statePath, n.state)
}

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
	s := &State{
		Events: map[string]Event{},
		Order:  []string{},
	}
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

// [Continue with all the private methods...]
// [Keeping same structure but adding support for new event types]

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

	// Handle different event types
	switch e.Typ {
	case "file_announce":
		if e.FileMeta != nil {
			n.handleFileAnnounce(&e)
		}
	case "file_request":
		if e.FileReq != nil {
			n.handleFileRequest(&e)
		}
	case "chunk":
		if e.ChunkRef != nil {
			n.handleChunk(&e)
		}
	}

	n.persistState()

	if n.eventHandler == nil {
		return
	}

	plain, ok := n.decryptEvent(&e)
	switch e.Typ {
	case `msg`:
		n.eventHandler(EventMessage, MessageEvent{
			Event:     &e,
			Timestamp: time.Unix(e.TS, 0),
			Author:    e.Author,
			Nick:      e.Nick,
			Body:      plain,
			Encrypted: !ok,
		})
	case `dm`:
		if e.Author == n.cfg.PubKeyB64 {
			n.eventHandler(EventDM, DMEvent{
				Event:     &e,
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
				Event:     &e,
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

func (n *Node) handleFileAnnounce(e *Event) {
	if e.FileMeta == nil || e.Author == n.cfg.PubKeyB64 {
		return // Don't process our own announcements
	}

	// Check if this is for us (DM) or global
	if e.To != "" && e.To != n.cfg.PubKeyB64 {
		return // Not for us
	}

	n.fileOffersMu.Lock()
	n.fileOffers[e.FileMeta.FileID] = &FileOffer{
		Meta:      e.FileMeta,
		From:      e.Author,
		Nick:      e.Nick,
		OfferTime: time.Unix(e.TS, 0),
		IsLocal:   false,
	}
	n.fileOffersMu.Unlock()

	if n.eventHandler != nil {
		n.eventHandler(EventFileOffer, FileOfferEvent{
			FileID:   e.FileMeta.FileID,
			FileName: e.FileMeta.Name,
			FileSize: e.FileMeta.Size,
			From:     e.Author,
			Nick:     e.Nick,
		})
	}
}

func (n *Node) handleFileRequest(e *Event) {
	if e.FileReq == nil {
		return
	}

	// Check if we have this file
	n.fileOffersMu.Lock()
	offer, ok := n.fileOffers[e.FileReq.FileID]
	if !ok || !offer.IsLocal {
		n.fileOffersMu.Unlock()
		return
	}
	n.fileOffersMu.Unlock()

	// Send chunks to requester
	go n.sendFileChunks(e.FileReq.FileID, e.FileReq.Requester)
}

func (n *Node) handleChunk(e *Event) {
	if e.ChunkRef == nil {
		return
	}

	// Check if this chunk is for us
	if e.ChunkRef.Requester != "" && e.ChunkRef.Requester != n.cfg.PubKeyB64 {
		return // Not for us
	}

	n.fileDownloadsMu.Lock()
	dl, ok := n.fileDownloads[e.ChunkRef.FileID]
	if !ok {
		n.fileDownloadsMu.Unlock()
		return
	}

	// Decode and store chunk
	if data, err := base64.StdEncoding.DecodeString(e.ChunkRef.Data); err == nil {
		dl.ReceivedChunks[e.ChunkRef.Index] = data

		// Check if complete
		if len(dl.ReceivedChunks) == dl.Meta.ChunkCount {
			dl.Complete = true

			if n.eventHandler != nil {
				n.eventHandler(EventFileComplete, FileCompleteEvent{
					FileID:   e.ChunkRef.FileID,
					FileName: dl.Meta.Name,
				})
			}
		} else if n.eventHandler != nil {
			// Progress update
			percent := float64(len(dl.ReceivedChunks)) / float64(dl.Meta.ChunkCount) * 100
			n.eventHandler(EventFileProgress, FileProgressEvent{
				FileID:         e.ChunkRef.FileID,
				FileName:       dl.Meta.Name,
				ReceivedChunks: len(dl.ReceivedChunks),
				TotalChunks:    dl.Meta.ChunkCount,
				Percent:        percent,
			})
		}
	}
	n.fileDownloadsMu.Unlock()
}

// ... continuing from handleChunk function ...

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
	dec.Buffer(make([]byte, 0, 65536), 10<<20) // Increased for file chunks

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
	dec.Buffer(make([]byte, 0, 65536), 10<<20)
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
	dec.Buffer(make([]byte, 0, 65536), 10<<20)
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
		Typ      string     `json:"type"`
		Author   string     `json:"author"`
		Nick     string     `json:"nick"`
		Body     string     `json:"body,omitempty"`
		To       string     `json:"to,omitempty"`
		TS       int64      `json:"ts"`
		Enc      *encDigest `json:"enc,omitempty"`
		FileMeta *FileMeta  `json:"file_meta,omitempty"`
		FileReq  *FileReq   `json:"file_req,omitempty"`
		ChunkRef *ChunkRef  `json:"chunk_ref,omitempty"`
	}
	var encD *encDigest
	if e.Enc != nil {
		encD = canonicalizeEnc(e.Enc)
	}
	j, _ := json.Marshal(bare{e.Typ, e.Author, e.Nick, e.Body, e.To, e.TS, encD, e.FileMeta, e.FileReq, e.ChunkRef})
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
