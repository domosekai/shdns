/*	shdns, a port of ChinaDNS in go with IPv6 support
	Copyright (C) 2019–2021 domosekai

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var localnet = flag.String("b", "localhost:5353", "Local binding address and UDP port (e.g. 127.0.0.1:5353 [::1]:5353)")
var dservers = flag.String("d", "114.114.114.114,223.5.5.5", "Domestic nameservers. Default port 53. Use format [IP]:port for IPv6.")
var fservers = flag.String("f", "8.8.8.8,8.8.4.4", "Foreign nameservers. Default port 53. Use format [IP]:port for IPv6.")
var trusted = flag.Bool("t", false, "Trustworthy mode. Foreign answers will not be checked for validity.")
var fast = flag.Bool("F", false, "Fast mode. Accept foreign IP from domestic nameservers if it passes basic checks.")
var ipnet4file = flag.String("l4", "", "Domestic IPv4 list file (one IP/CIDR each line) (Required)")
var ipnet6file = flag.String("l6", "", "Domestic IPv6 list file (one IP/CIDR each line)")
var blacklist4file = flag.String("k4", "", "IPv4 blacklist file for all nameservers (one IP/CIDR each line)")
var blacklist6file = flag.String("k6", "", "IPv6 blacklist file for all nameservers (one IP/CIDR each line)")
var minrtt = flag.Int("m", 30, "Minimum possible RTT (ms) for foreign nameservers. Packets with shorter RTT will be dropped.")
var minsafe = flag.Int("s", 100, "Minimum safe RTT (ms) for foreign nameservers. Packets with longer RTT will be immediately accepted. Packets with shorter RTT will be delayed until this threshold.")
var minwait = flag.Int("w", 100, "Time (ms) during which domestic answers are prioritized. Usually used with a local caching resolver.")
var timeout = flag.Int("M", 3000, "DNS query timeout (ms). Use a larger value for high-latency network or DNS-over-HTTPS.")
var reversenet = flag.String("r", "", "Address and port for listening to reverse DNS queries from cache")
var cachelife = flag.Int("c", 60, "DNS cache lifetime (minutes) for reverse lookup")
var verbose = flag.Bool("v", false, "Verbose mode. Connection will remain open after replied until timeout.")
var showver = flag.Bool("V", false, "Show version")
var conffile = flag.String("C", "", "Configuration file (dnsmasq-style)")
var version = "unknown"
var builddate = "unknown"

type serverType int

const (
	domestic serverType = iota
	foreign
)

type nameserver struct {
	udpAddr *net.UDPAddr
	sType   serverType
}

type answer struct {
	payload []byte
	sType   serverType
	ips     []net.IP
	ns      string // endpoint that produced this answer
}

var (
	cnIPNet4, cnIPNet6   []net.IPNet
	blackIPs4, blackIPs6 []net.IPNet
	servers              []nameserver
	reverseTable         cache
	logger               = log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lmicroseconds)
	errlog               = log.New(os.Stderr, "", log.Ldate|log.Ltime|log.Lmicroseconds)
	ipsetSpecs           []ipsetSpec
	nftSetSpecs          []nftSetSpec
	parsedIPSetSpecs     []ipsetSpec
	parsedNFTSetSpecs    []nftSetSpec
)

func main() {
	flag.Parse()
	if *showver {
		fmt.Printf("shdns version %s (built %s)\n", version, builddate)
		return
	}
	if flag.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Build set of explicitly provided CLI flags
	cliSet := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) {
		cliSet[f.Name] = true
	})

	// Load config file if specified
	if *conffile != "" {
		cfg, err := parseConfig(*conffile)
		if err != nil {
			errlog.Fatalf("Config file error: %v", err)
		}
		if err := applyConfig(cfg, cliSet); err != nil {
			errlog.Fatalf("Config file error: %v", err)
		}
	}

	// Ensure at least one way to provide config exists
	if len(os.Args) == 1 && *conffile == "" {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	if err := loadConfig(); err != nil {
		errlog.Fatalln(err)
	}

	if len(ipsetSpecs) > 0 {
		ipsetInit()
		defer ipsetClose()
	}
	if len(nftSetSpecs) > 0 {
		nftInit()
		defer nftClose()
	}

	addr, err := parseUDPAddr(*localnet)
	if err != nil {
		errlog.Fatalf("Invalid binding address: %s", *localnet)
	}
	inConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		errlog.Fatalln(err)
	}
	defer inConn.Close()
	logger.Printf("Listening on UDP %s", addr)
	if *reversenet != "" {
		reverseTable.table = make(map[string]cacheEntry)
		if addr, err := net.ResolveUDPAddr("udp", *reversenet); err == nil {
			conn, err := net.ListenUDP("udp", addr)
			if err == nil {
				go func() {
					ticker := time.Tick(15 * time.Minute)
					for range ticker {
						reverseTable.purge(time.Minute * time.Duration(*cachelife))
					}
				}()
				go handleReverse(conn)
			}
		}
	}

	// Handle SIGHUP for config reload
	sigHup := make(chan os.Signal, 1)
	signal.Notify(sigHup, syscall.SIGHUP)
	go func() {
		for range sigHup {
			logger.Print("Received SIGHUP, reloading configuration...")
			reloadConfig()
		}
	}()

	for {
		var payload [1500]byte
		if n, addr, err := inConn.ReadFromUDP(payload[:]); err != nil {
			errlog.Println(err)
			continue
		} else {
			go handleQuery(addr, payload[:n], inConn)
		}
	}
}
