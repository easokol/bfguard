package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"sigs.k8s.io/knftables"
)

const (
	tableName   = "nft-blacklist"
	setNameV4   = "blacklist_v4"
	setNameV6   = "blacklist_v6"
	chainInput  = "input"
	chainOutput = "output"
    baseTableName    = "nft-baserules"
    baseChainInput   = "input"
    baseChainOutput  = "output"
    baseCounterInput = "cnt_invalid_input"
    baseCounterOutput = "cnt_invalid_output"
)

var timeoutValue = 48 * time.Hour // 2 days

// Config holds everything read from the JSON file.
type Config struct {
	TCPPorts   []int    `json:"tcp_ports"`
	UDPPorts   []int    `json:"udp_ports"`
	Whitelist4 []string `json:"whitelist4"` // CIDR strings (e.g. "192.168.0.0/24")
	Whitelist6 []string `json:"whitelist6"`
}

var (
	// parsed whitelist networks for fast Go‑side checks.
	whitelistNets []*net.IPNet
)

func main() {
	// command‑line flags
	configPath := flag.String("config", "config.json", "path to JSON config file")
	flag.Parse()

	// load configuration
	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to read config: %v", err)
	}
	log.Printf("Loaded config: TCP ports=%v UDP ports=%v whitelist=%v",
		cfg.TCPPorts, cfg.UDPPorts, cfg.Whitelist4)

	// create nftables infrastructure (tables, sets, chains, rules, counters)
	if err := createInfrastructure(cfg); err != nil {
		log.Fatalf("Failed to set up nftables: %v", err)
	}
	log.Println("nftables blacklist & whitelist sets and rules ready")

    if err := createInfrastructure(cfg); err != nil {
        log.Fatalf("Failed to set up nftables: %v", err)
    }
    log.Println("nftables blacklist & whitelist sets and rules ready")

    // создаём таблицу базовых правил
    if err := createBaseRules(); err != nil {
        log.Fatalf("Failed to set up base nftables rules: %v", err)
    }
    log.Println("Base security rules (invalid state drop) installed")
	
	// start TCP and UDP listeners
	var wg sync.WaitGroup

	for _, p := range cfg.TCPPorts {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			startTCPListener(port)
		}(p)
	}
	for _, p := range cfg.UDPPorts {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			startUDPListener(port)
		}(p)
	}

	// graceful shutdown on SIGINT / SIGTERM
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		s := <-sigc
		log.Printf("Received %s – shutting down...", s)
		os.Exit(0)
	}()

	wg.Wait()
}

// loadConfig reads JSON into Config and also parses whitelist CIDRs.
func loadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cfg Config
	dec := json.NewDecoder(f)
	if err := dec.Decode(&cfg); err != nil {
		return nil, err
	}

	// Parse whitelist CIDR strings into net.IPNet objects.
	for _, cidr := range cfg.Whitelist4 {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("[WARN] Invalid whitelist entry %q – skipping", cidr)
			continue
		}
		whitelistNets = append(whitelistNets, ipnet)
	}
	for _, cidr := range cfg.Whitelist6 {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("[WARN] Invalid whitelist entry %q – skipping", cidr)
			continue
		}
		whitelistNets = append(whitelistNets, ipnet)
	}
	return &cfg, nil
}

// startTCPListener opens a TCP socket on the given port and accepts connections.
// Each accepted connection triggers blacklisting of the remote IP (unless whitelisted).
func startTCPListener(port int) {
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen TCP on %s: %v", addr, err)
	}
	defer l.Close()
	log.Printf("Listening TCP on %s", addr)

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("[WARN] TCP accept error: %v", err)
			continue
		}
		remoteIP := extractIP(conn.RemoteAddr())
		go func(c net.Conn, ip string) {
			defer c.Close()
			if isWhitelisted(ip) {
				return
			}
			if tcpConn, ok := c.(*net.TCPConn); ok {
				tcpConn.SetLinger(0) // принудительный RST при закрытии
			}
			if isIPv6(ip) {
				_ = addToBlacklistV6(ip)
			} else {
				_ = addToBlacklistV4(ip)
			}
		}(conn, remoteIP)
	}
}

// startUDPListener opens a UDP socket on the given port and reads packets.
// Each packet triggers blacklisting of its source IP (unless whitelisted).
func startUDPListener(port int) {
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Fatalf("Failed to listen UDP on %s: %v", addr, err)
	}
	defer pc.Close()
	log.Printf("Listening UDP on %s", addr)

	buf := make([]byte, 2048)
	for {
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			log.Printf("[WARN] UDP read error: %v", err)
			continue
		}
		_ = n // payload ignored
		ip := extractIP(src)
		if isWhitelisted(ip) {
			continue
		}
		if isIPv6(ip) {
			_ = addToBlacklistV6(ip)
		} else {
			_ = addToBlacklistV4(ip)
		}
	}
}

// extractIP returns the string representation of an IP address from net.Addr.
func extractIP(addr net.Addr) string {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP.String()
	case *net.UDPAddr:
		return a.IP.String()
	default:
		s := addr.String()
		if host, _, err := net.SplitHostPort(s); err == nil {
			return host
		}
		return s
	}
}

// isWhitelisted checks if the given IP string belongs to any whitelist network.
func isWhitelisted(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range whitelistNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// isIPv6 returns true if the IP string represents an IPv6 address.
func isIPv6(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	return ip != nil && ip.To4() == nil
}

func createBaseRules() error {
    nft, err := knftables.New(knftables.InetFamily, baseTableName)
    if err != nil {
        return fmt.Errorf("failed to create knftables interface for base rules: %w", err)
    }

    ctx := context.Background()
    tx := nft.NewTransaction()

    // Таблица
    tx.Add(&knftables.Table{
        Comment: knftables.PtrTo("Base security rules (invalid state drop)"),
    })

    // Счётчики
    tx.Add(&knftables.Counter{
        Name:    baseCounterInput,
        Comment: knftables.PtrTo("Count dropped input packets with invalid state"),
    })
    tx.Add(&knftables.Counter{
        Name:    baseCounterOutput,
        Comment: knftables.PtrTo("Count dropped output packets with invalid state"),
    })

    // Цепочки с приоритетом -2 (выполняются до цепочек с приоритетом -1)
    hookInput := knftables.BaseChainHook("input")
    hookOutput := knftables.BaseChainHook("output")
    chainType := knftables.BaseChainType("filter")
    prio := knftables.BaseChainPriority("-2")

    tx.Add(&knftables.Chain{
        Name:     baseChainInput,
        Type:     &chainType,
        Hook:     &hookInput,
        Priority: &prio,
        Comment:  knftables.PtrTo("Input chain for base rules"),
    })
    tx.Add(&knftables.Chain{
        Name:     baseChainOutput,
        Type:     &chainType,
        Hook:     &hookOutput,
        Priority: &prio,
        Comment:  knftables.PtrTo("Output chain for base rules"),
    })

    // Правила с использованием именованных счётчиков
    tx.Add(&knftables.Rule{
        Chain: baseChainInput,
        Rule:  fmt.Sprintf("ct state invalid counter name %s drop", baseCounterInput),
        Comment: knftables.PtrTo("Drop packets with invalid connection state (input)"),
    })
    tx.Add(&knftables.Rule{
        Chain: baseChainOutput,
        Rule:  fmt.Sprintf("ct state invalid counter name %s drop", baseCounterOutput),
        Comment: knftables.PtrTo("Drop packets with invalid connection state (output)"),
    })

    // Применяем транзакцию
    err = nft.Run(ctx, tx)
    if err != nil && !knftables.IsAlreadyExists(err) {
        return fmt.Errorf("failed to apply base nftables rules: %w", err)
    }
    return nil
}

// addToBlacklistV4 adds an IPv4 address or subnet to the blacklist_v4 set.
func addToBlacklistV4(ip string) error {
	nft, err := knftables.New(knftables.InetFamily, tableName)
	if err != nil {
		return fmt.Errorf("failed to create knftables interface: %w", err)
	}

	tx := nft.NewTransaction()
	tx.Add(&knftables.Element{
		Set: setNameV4,
		Key: []string{ip},
	})

	ctx := context.Background()
	err = nft.Run(ctx, tx)
	if err != nil && !knftables.IsAlreadyExists(err) {
		return fmt.Errorf("failed to add element to set %s: %w", setNameV4, err)
	}
	return nil
}

// addToBlacklistV6 adds an IPv6 address or subnet to the blacklist_v6 set.
func addToBlacklistV6(ip string) error {
	nft, err := knftables.New(knftables.InetFamily, tableName)
	if err != nil {
		return fmt.Errorf("failed to create knftables interface: %w", err)
	}

	tx := nft.NewTransaction()
	tx.Add(&knftables.Element{
		Set: setNameV6,
		Key: []string{ip},
	})

	ctx := context.Background()
	err = nft.Run(ctx, tx)
	if err != nil && !knftables.IsAlreadyExists(err) {
		return fmt.Errorf("failed to add element to set %s: %w", setNameV6, err)
	}
	return nil
}

func createInfrastructure(cfg *Config) error {
    nft, err := knftables.New(knftables.InetFamily, tableName)
    if err != nil {
        return fmt.Errorf("failed to create knftables interface: %w", err)
    }

    ctx := context.Background()
    tx := nft.NewTransaction()

    tx.Add(&knftables.Table{
        Comment: knftables.PtrTo("Table created by nft-blacklist Go port"),
    })

    // 2. blacklists
    tx.Add(&knftables.Set{
        Name:    setNameV4,
        Type:    "ipv4_addr",
        Flags:   []knftables.SetFlag{knftables.IntervalFlag, knftables.TimeoutFlag},
        Timeout: &timeoutValue,
        Comment: knftables.PtrTo("IPv4 blacklist with auto-merge"),
    })
    tx.Add(&knftables.Set{
        Name:    setNameV6,
        Type:    "ipv6_addr",
        Flags:   []knftables.SetFlag{knftables.IntervalFlag, knftables.TimeoutFlag},
        Timeout: &timeoutValue,
        Comment: knftables.PtrTo("IPv6 blacklist with auto-merge"),
    })

    // 3. Named Counters
    tx.Add(&knftables.Counter{
        Name:    setNameV4,
        Comment: knftables.PtrTo("Counter for IPv4 blacklist drops"),
    })
    tx.Add(&knftables.Counter{
        Name:    setNameV6,
        Comment: knftables.PtrTo("Counter for IPv6 blacklist drops"),
    })

    // 4. Chains
    hookInput := knftables.BaseChainHook("input")
    hookOutput := knftables.BaseChainHook("output")
    chainType := knftables.BaseChainType("filter")
    prio := knftables.BaseChainPriority("-1") // filter - 1

    tx.Add(&knftables.Chain{
        Name:     chainInput,
        Type:     &chainType,
        Hook:     &hookInput,
        Priority: &prio,
        Comment:  knftables.PtrTo("Input chain for blacklist"),
    })
    tx.Add(&knftables.Chain{
        Name:     chainOutput,
        Type:     &chainType,
        Hook:     &hookOutput,
        Priority: &prio,
        Comment:  knftables.PtrTo("Output chain for blacklist"),
    })

    // 5. Rules
    tx.Add(&knftables.Rule{
        Chain: chainInput,
        Rule:  "iif lo accept",
    })
    tx.Add(&knftables.Rule{
        Chain: chainInput,
        Rule:  "meta pkttype { broadcast, multicast } accept",
    })
    if len(cfg.Whitelist4) > 0 {
        rule := fmt.Sprintf("ip saddr { %s } accept", strings.Join(cfg.Whitelist4, ", "))
        tx.Add(&knftables.Rule{
            Chain: chainInput,
            Rule:  rule,
        })
    }
    if len(cfg.Whitelist6) > 0 {
        rule := fmt.Sprintf("ip6 saddr { %s } accept", strings.Join(cfg.Whitelist6, ", "))
        tx.Add(&knftables.Rule{
            Chain: chainInput,
            Rule:  rule,
        })
    }
    tx.Add(&knftables.Rule{
        Chain: chainInput,
        Rule:  fmt.Sprintf("ip saddr @%s counter name %s reject with icmp port-unreachable", setNameV4, setNameV4),
    })
    tx.Add(&knftables.Rule{
        Chain: chainInput,
        Rule:  fmt.Sprintf("ip6 saddr @%s counter name %s reject with icmpv6 port-unreachable", setNameV6, setNameV6),
    })

    tx.Add(&knftables.Rule{
        Chain: chainOutput,
        Rule:  "oif lo accept",
    })
    tx.Add(&knftables.Rule{
        Chain: chainOutput,
        Rule:  "meta pkttype { broadcast, multicast } accept",
    })
    if len(cfg.Whitelist4) > 0 {
        rule := fmt.Sprintf("ip daddr { %s } accept", strings.Join(cfg.Whitelist4, ", "))
        tx.Add(&knftables.Rule{
            Chain: chainOutput,
            Rule:  rule,
        })
    }
    if len(cfg.Whitelist6) > 0 {
        rule := fmt.Sprintf("ip6 daddr { %s } accept", strings.Join(cfg.Whitelist6, ", "))
        tx.Add(&knftables.Rule{
            Chain: chainOutput,
            Rule:  rule,
        })
    }
    tx.Add(&knftables.Rule{
        Chain: chainOutput,
        Rule:  fmt.Sprintf("ip daddr @%s counter name %s reject with icmp port-unreachable", setNameV4, setNameV4),
    })
    tx.Add(&knftables.Rule{
        Chain: chainOutput,
        Rule:  fmt.Sprintf("ip6 daddr @%s counter name %s reject with icmpv6 port-unreachable", setNameV6, setNameV6),
    })

    // 6. Apply
    err = nft.Run(ctx, tx)
    if err != nil && !knftables.IsAlreadyExists(err) {
        return fmt.Errorf("failed to apply nftables rules: %w", err)
    }
    return nil
}
