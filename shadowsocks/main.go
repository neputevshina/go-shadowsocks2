package shadowsocks

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

	"github.com/neputevshina/go-shadowsocks2/core"
	"github.com/neputevshina/go-shadowsocks2/socks"
)

type Config struct {
	Verbose    bool
	UDPTimeout time.Duration
	TCPCork    bool
}

var config Config
var logger *log.Logger

type Flags struct {
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

func Main(flags Flags, conf Config, logs *log.Logger) {
	logger = logs
	config = conf
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
			logger.Fatal(err)
		}
		key = k
	}

	if flags.Client != nil { // client mode
		var err error

		addr, cipher, password := parseURL(*flags.Client)

		udpAddr := addr

		ciph, err := core.PickCipher(cipher, key, password)
		if err != nil {
			logger.Fatal(err)
		}

		if flags.Plugin != "" {
			addr, err = startPlugin(flags.Plugin, flags.PluginOpts, addr, false)
			if err != nil {
				logger.Fatal(err)
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
				logger.Fatal(err)
			}
		}

		ciph, err := core.PickCipher(cipher, key, password)
		if err != nil {
			logger.Fatal(err)
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
		logger.Println("must provide cipher")
		fail = true
	}
	if password == "" {
		logger.Println("must provide password")
		fail = true
	}
	if addr == "" {
		logger.Println("must provide server address and port")
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
			logger.Println(`can't recognize passed url`)
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
