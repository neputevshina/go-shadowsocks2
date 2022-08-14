package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

var config struct {
	Verbose    bool
	UDPTimeout time.Duration
	TCPCork    bool
}

func main() {

	var flags struct {
		Client     *string
		Server     *string
		Cipher     string
		Key        string
		Password   string
		Keygen     int
		Socks      string
		RedirTCP   string
		RedirTCP6  string
		TCPTun     string
		UDPTun     string
		UDPSocks   bool
		UDP        bool
		TCP        bool
		Plugin     string
		PluginOpts string
	}

	flags.Server = flag.String("s", "0.0.0.0", "server listen address")
	flags.Client = flag.String("c", "", "client connect url")

	flag.BoolVar(&config.Verbose, "verbose", false, "verbose mode")
	flag.StringVar(&flags.Cipher, "cipher", "AEAD_CHACHA20_POLY1305", "available ciphers: "+strings.Join(core.ListCipher(), " "))
	flag.StringVar(&flags.Key, "key", "", "base64url-encoded key (derive from password if empty)")
	flag.IntVar(&flags.Keygen, "keygen", 0, "generate a base64url-encoded random key of given length in byte")
	flag.StringVar(&flags.Password, "password", "", "password")
	flag.StringVar(&flags.Socks, "socks", "", "(client-only) SOCKS listen address")
	flag.BoolVar(&flags.UDPSocks, "u", false, "(client-only) Enable UDP support for SOCKS")
	flag.StringVar(&flags.RedirTCP, "redir", "", "(client-only) redirect TCP from this address")
	flag.StringVar(&flags.RedirTCP6, "redir6", "", "(client-only) redirect TCP IPv6 from this address")
	flag.StringVar(&flags.TCPTun, "tcptun", "", "(client-only) TCP tunnel (laddr1=raddr1,laddr2=raddr2,...)")
	flag.StringVar(&flags.UDPTun, "udptun", "", "(client-only) UDP tunnel (laddr1=raddr1,laddr2=raddr2,...)")
	flag.StringVar(&flags.Plugin, "plugin", "", "Enable SIP003 plugin. (e.g., v2ray-plugin)")
	flag.StringVar(&flags.PluginOpts, "plugin-opts", "", "Set SIP003 plugin options. (e.g., \"server;tls;host=mydomain.me\")")
	flag.BoolVar(&flags.UDP, "udp", false, "(server-only) enable UDP support")
	flag.BoolVar(&flags.TCP, "tcp", true, "(server-only) enable TCP support")
	flag.BoolVar(&config.TCPCork, "tcpcork", false, "coalesce writing first few packets")
	flag.DurationVar(&config.UDPTimeout, "udptimeout", 5*time.Minute, "UDP tunnel timeout")
	flag.Parse()

	if flags.Keygen > 0 {
		key := make([]byte, flags.Keygen)
		io.ReadFull(rand.Reader, key)
		fmt.Println(base64.URLEncoding.EncodeToString(key))
		return
	}

	if flags.Client == nil && flags.Server == nil {
		flag.Usage()
		return
	}

	var key []byte
	if flags.Key != "" {
		k, err := base64.URLEncoding.DecodeString(flags.Key)
		if err != nil {
			log.Fatal(err)
		}
		key = k
	}

	if flags.Client != nil { // client mode
		var err error

		addr, cipher, password := parseURL(*flags.Client)

		udpAddr := addr

		ciph, err := core.PickCipher(cipher, key, password)
		if err != nil {
			log.Fatal(err)
		}

		if flags.Plugin != "" {
			addr, err = startPlugin(flags.Plugin, flags.PluginOpts, addr, false)
			if err != nil {
				log.Fatal(err)
			}
		}

		if flags.UDPTun != "" {
			for _, tun := range strings.Split(flags.UDPTun, ",") {
				p := strings.Split(tun, "=")
				go udpLocal(p[0], udpAddr, p[1], ciph.PacketConn)
			}
		}

		if flags.TCPTun != "" {
			for _, tun := range strings.Split(flags.TCPTun, ",") {
				p := strings.Split(tun, "=")
				go tcpTun(p[0], addr, p[1], ciph.StreamConn)
			}
		}

		if flags.Socks != "" {
			socks.UDPEnabled = flags.UDPSocks
			println(addr)
			go socksLocal(flags.Socks, addr, ciph.StreamConn)
			if flags.UDPSocks {
				go udpSocksLocal(flags.Socks, udpAddr, ciph.PacketConn)
			}
		}

		if flags.RedirTCP != "" {
			go redirLocal(flags.RedirTCP, addr, ciph.StreamConn)
		}

		if flags.RedirTCP6 != "" {
			go redir6Local(flags.RedirTCP6, addr, ciph.StreamConn)
		}
	}

	if flags.Server != nil { // server mode
		addr := *flags.Server
		cipher := flags.Cipher
		password := flags.Password
		var err error

		udpAddr := addr

		if flags.Plugin != "" {
			addr, err = startPlugin(flags.Plugin, flags.PluginOpts, addr, true)
			if err != nil {
				log.Fatal(err)
			}
		}

		ciph, err := core.PickCipher(cipher, key, password)
		if err != nil {
			log.Fatal(err)
		}

		if flags.UDP {
			go udpRemote(udpAddr, ciph.PacketConn)
		}
		if flags.TCP {
			go tcpRemote(addr, ciph.StreamConn)
		}
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	killPlugin()
}

var formats = `	Supported formats:
	- ss://<cipher>:<password>@<server ip>:<port>[/<anything>]
	- ss://<base-64 encoded cipher and password>@<server ip>:<port>[/<anything>] (Outline)
	- ss://<base-64 encoded connection data>[#<optional tag>]`

//var plainRegexp = regexp.MustCompile(`ss://([A-Z_0-9]+):(.+)@(.+:[0-9]{1,6})`)

func parseURL(s string) (addr, cipher, password string) {
	fail := false
	addr, cipher, password = parseurl(s)
	if cipher == "" {
		log.Println("must provide cipher")
		fail = true
	}
	if password == "" {
		log.Println("must provide password")
		fail = true
	}
	if addr == "" {
		log.Println("must provide server address and port")
		fail = true
	}
	if fail {
		os.Exit(1)
	}
	return
}

var base64Regexp = regexp.MustCompile(`ss://([A-Za-z_0-9-]+)(#(.+))?$`)
var base64DecodedRegexp = regexp.MustCompile(`(.+):(.+)@(.+:[0-9]{1,6})`)
var outlineRegexp = regexp.MustCompile(`ss://([A-Za-z_0-9-]+)@(.+:[0-9]{1,6})`)

func parseurl(s string) (addr, cipher, password string) {
	defer func() {
		if err := recover(); err != nil {
			log.Println(`can't recognize passed url`)
			fmt.Println(formats)
			panic(err)
		}
	}()

	if ss := base64Regexp.FindStringSubmatch(s); base64Regexp.MatchString(s) {
		dat, err := base64.RawURLEncoding.DecodeString(ss[1])
		if err != nil {
			panic(dat)
		}
		// Shadowsocks config “specification” gives an example of a password containing
		// a slash, a semicolon and an '@'.
		// Let's suppose that someone actually generated a password containing
		// those characters and not try to parse it as an URL.
		so := base64DecodedRegexp.FindSubmatch(dat)
		if so == nil {
			panic("")
		}
		cipher = string(so[1])
		password = string(so[2])
		addr = string(ss[2])
		return
	} else if ss := outlineRegexp.FindStringSubmatch(s); outlineRegexp.MatchString(s) {
		dat, err := base64.RawURLEncoding.DecodeString(ss[1])
		if err != nil {
			panic("")
		}
		bs := bytes.Split(dat, []byte{':'})
		cipher = string(bs[0])
		password = string(bs[1])
		addr = string(ss[2])
		return
	}

	u, err := url.Parse(s)
	if err != nil {
		panic("")
	}
	if u.User == nil {
		return u.Host, "", ""
	}
	passw, _ := u.User.Password()
	return u.Host, u.User.Username(), passw
}
