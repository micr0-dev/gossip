package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	qrterminal "github.com/mdp/qrterminal/v3"
)

func main() {
	var (
		iface = flag.String("iface", "tun0", "Yggdrasil interface (e.g. tun0 or ygg0)")
		port  = flag.Int("port", 19999, "TCP port to listen on (IPv6)")
		state = flag.String("state", "./gossip_state.json", "Path to state JSON")
		conf  = flag.String("config", "./gossip_config.json", "Path to config JSON")
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
		node.AddPeer(*peer)
	}

	// Set up event handler for displaying messages
	node.SetEventHandler(func(eventType EventType, data interface{}) {
		switch eventType {
		case EventMessage:
			msg := data.(MessageEvent)
			if msg.Encrypted {
				fmt.Printf("[%s][global] %s: [encrypted—no access]\n",
					msg.Timestamp.Format("15:04:05"),
					displayFrom(msg.Nick, msg.Author))
			} else {
				fmt.Printf("[%s][global] %s: %s\n",
					msg.Timestamp.Format("15:04:05"),
					displayFrom(msg.Nick, msg.Author),
					msg.Body)
			}
		case EventDM:
			dm := data.(DMEvent)
			if dm.Incoming {
				if dm.Encrypted {
					fmt.Printf("[%s] ✉️ from %s: [encrypted—cannot decrypt]\n",
						dm.Timestamp.Format("15:04:05"),
						displayFrom(dm.Nick, dm.Author))
				} else {
					fmt.Printf("[%s] ✉️ from %s: %s\n",
						dm.Timestamp.Format("15:04:05"),
						displayFrom(dm.Nick, dm.Author),
						dm.Body)
				}
			} else {
				if dm.Encrypted {
					fmt.Printf("[%s] ✉️ to %s: [encrypted]\n",
						dm.Timestamp.Format("15:04:05"),
						targetLabel(node, dm.To))
				} else {
					fmt.Printf("[%s] ✉️ to %s: %s\n",
						dm.Timestamp.Format("15:04:05"),
						targetLabel(node, dm.To),
						dm.Body)
				}
			}
		case EventPeerRequest:
			req := data.(PeerRequestEvent)
			fmt.Printf("[request] %s (%s) asks to peer: %s — /accept %s\n",
				displayFromPub(req.Nick, req.Pub),
				ShortKey(req.Pub),
				displayAddr(req.Addr),
				ShortKey(req.Pub))
		case EventPeerAccepted:
			pub := data.(string)
			contacts := node.GetContacts()
			var c *Contact
			for _, contact := range contacts {
				if contact.Pub == pub {
					c = &contact
					break
				}
			}
			if c != nil {
				fmt.Printf("[ok] %s (%s) accepted you\n",
					prettyContact(c),
					ShortKey(pub))
			} else {
				fmt.Printf("[ok] peer accepted you (%s)\n", ShortKey(pub))
			}
		case EventError:
			err := data.(error)
			fmt.Printf("[ERR] %v\n", err)
		}
	})

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Start the server
	go func() {
		if err := node.ListenAndServe(); err != nil {
			fmt.Println("server error:", err)
			node.Shutdown()
		}
	}()

	// Print startup info
	fmt.Printf("gossip v%s | nick=%q | id=%s\n", Version, node.GetNick(), ShortKey(node.GetPublicKeyB64()))
	fmt.Printf("Address: [%s]:%d (iface=%s)\n", node.GetYggIP().String(), node.GetPort(), node.GetInterface())
	fmt.Printf("Peers: %v\n", node.ListPeers())
	fmt.Println("Tip: /link to print a QR; /accept <gossip://…> to connect; /pending then /accept <SHORTID> to approve.")

	// Start REPL
	go repl(node)

	select {
	case <-ctx.Done():
	case <-node.quit:
	}
	fmt.Println("\nshutting down...")
}

func repl(node *Node) {
	in := bufio.NewReader(os.Stdin)
	fmt.Printf("Type text to chat [global]. Use /help for commands.\n")
	for {
		fmt.Printf("[%s@%s] > ", node.GetNick(), last4(node.GetYggIP()))
		line, err := in.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				fmt.Println()
				node.Shutdown()
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
			handleCommand(node, line)
			continue
		}
		node.SendGlobal(line)
	}
}

func handleCommand(node *Node, line string) {
	parts := strings.Fields(line)
	cmd := strings.ToLower(strings.TrimPrefix(parts[0], "/"))
	switch cmd {
	case "help":
		fmt.Println(`Commands:
  /link                   show your gossip:// link + QR
  /accept <link|pub|id>   accept pending OR connect using a link
  /pending                list pending peer requests
  /contacts               list known contacts
  /peers                  list peer addresses
  /unpeer <pub|id>        remove acceptance + drop stored peer addr
  /nick <name>            set nickname
  /msg <who> <text>       DM to nick|SHORTID|pubkey
  /r <text>               reply to last incoming DM
  /save                   save state
  /quit                   exit`)
	case "link":
		showLinkQR(node)
	case "pending":
		pending := node.GetPendingRequests()
		if len(pending) == 0 {
			fmt.Println("(no pending requests)")
		}
		for _, c := range pending {
			fmt.Printf(" - %s (%s) addr=%s seen=%s\n",
				displayFromPub(c.Nick, c.Pub),
				ShortKey(c.Pub),
				displayAddr(c.Addr),
				c.LastSeen.Format("15:04:05"))
		}
	case "contacts":
		contacts := node.GetContacts()
		if len(contacts) == 0 {
			fmt.Println("(no contacts yet)")
		} else {
			for _, c := range contacts {
				acc := "no"
				if c.Accepted {
					acc = "yes"
				}
				enc := "noekey"
				if c.EncPub != "" {
					enc = "ekey"
				}
				fmt.Printf(" - %s (%s) addr=%s accepted=%s enc=%s\n",
					displayFromPub(c.Nick, c.Pub),
					ShortKey(c.Pub),
					displayAddr(c.Addr),
					acc, enc)
			}
		}
	case "accept":
		if len(parts) < 2 {
			fmt.Println("usage: /accept <gossip://... | pubkey | SHORTID>")
			return
		}
		arg := strings.TrimSpace(strings.TrimPrefix(line, "/accept"))
		if strings.HasPrefix(arg, "gossip://") {
			err := node.AcceptPeerByLink(arg)
			if err != nil {
				fmt.Println("[err]", err)
			} else {
				addr, pub, nick, _ := ParseLink(arg)
				fmt.Printf("[ok] added peer %s", displayAddr(addr))
				if pub != "" {
					fmt.Printf(" and accepted %s (%s)", nickOrShort(pub, nick), ShortKey(pub))
				}
				fmt.Println()
			}
		} else {
			err := node.AcceptPeer(arg)
			if err != nil {
				fmt.Println("[err]", err)
			} else {
				fmt.Printf("[ok] accepted peer\n")
			}
		}
	case "unpeer":
		if len(parts) < 2 {
			fmt.Println("usage: /unpeer <pub|SHORTID>")
			return
		}
		err := node.UnpeerContact(parts[1])
		if err != nil {
			fmt.Println("[err]", err)
		} else {
			fmt.Printf("[ok] unpeered %s\n", ShortKey(parts[1]))
		}
	case "peers":
		for _, p := range node.ListPeers() {
			fmt.Println(" -", p)
		}
	case "nick":
		if len(parts) < 2 {
			fmt.Println("usage: /nick <name>")
			return
		}
		newNick := strings.TrimSpace(strings.TrimPrefix(line, "/nick"))
		node.SetNick(newNick)
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
		err := node.SendDMByWho(who, text)
		if err != nil {
			fmt.Println("[err]", err)
		}
	case "r":
		if len(parts) < 2 {
			fmt.Println("usage: /r <text>")
			return
		}
		text := strings.TrimSpace(strings.TrimPrefix(line, "/r"))
		err := node.ReplyToLastDM(text)
		if err != nil {
			fmt.Println("[err]", err)
		}
	case "save":
		node.SaveState()
		fmt.Println("[ok] saved")
	case "quit", "exit":
		node.Shutdown()
	default:
		fmt.Println("unknown command. /help for help")
	}
}

func showLinkQR(node *Node) {
	link := node.BuildLink()
	fmt.Println("Share this link (or QR) so friends can connect & send you a peer request:")
	fmt.Println(link, "\n")
	qrterminal.GenerateWithConfig(link, qrterminal.Config{
		Level:     qrterminal.M,
		Writer:    os.Stdout,
		BlackChar: qrterminal.BLACK,
		WhiteChar: qrterminal.WHITE,
		QuietZone: 1,
	})
	fmt.Println()
}

// ---------- Display helpers ----------

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

func displayFrom(nick, authorB64 string) string {
	b, err := base64.StdEncoding.DecodeString(authorB64)
	if err != nil || len(b) < 3 {
		if nick == "" {
			nick = "anon"
		}
		return fmt.Sprintf("%s~BADKEY", nick)
	}
	hexid := strings.ToUpper(hex.EncodeToString(b[:3]))
	if nick == "" {
		nick = "anon"
	}
	return fmt.Sprintf("%s~%s", nick, hexid)
}

func displayFromPub(nick, pub string) string {
	return displayFrom(nick, pub)
}

func targetLabel(node *Node, toB64 string) string {
	contacts := node.GetContacts()
	for _, c := range contacts {
		if c.Pub == toB64 && c.Nick != "" {
			return fmt.Sprintf("%s~%s", c.Nick, ShortKey(toB64))
		}
	}
	return "~" + ShortKey(toB64)
}

func prettyContact(c *Contact) string {
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

func displayAddr(addr string) string {
	if addr == "" {
		return "(no-addr)"
	}
	return addr
}

func nickOrShort(pub, nick string) string {
	if nick != "" {
		return nick
	}
	return "~" + ShortKey(pub)
}
