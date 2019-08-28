/*	shdns, a port of ChinaDNS in go with IPv6 support
	Copyright (C) 2019 domosekai

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
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"time"
)

var localnet = flag.String("b", "localhost:5353", "Local binding address and UDP port (e.g. 127.0.0.1:5353 [::1]:5353)")
var dservers = flag.String("d", "114.114.114.114:53,223.5.5.5:53", "Domestic nameservers. Use format [IP]:port for IPv6.")
var fservers = flag.String("f", "8.8.8.8:53,1.1.1.1:53", "Foreign nameservers. Use format [IP]:port for IPv6.")
var trusted = flag.Bool("t", false, "Trustworthy mode. Foreign answers will not be checked for validity.")
var ipnet4file = flag.String("l4", "", "Domestic IPv4 list file (one IP/CIDR each line) (Required)")
var ipnet6file = flag.String("l6", "", "Domestic IPv6 list file (one IP/CIDR each line)")
var blacklist4file = flag.String("k4", "", "IPv4 blacklist file for all nameservers (one IP/CIDR each line)")
var blacklist6file = flag.String("k6", "", "IPv6 blacklist file for all nameservers (one IP/CIDR each line)")
var minrtt = flag.Int("m", 30, "Minimum possible RTT (ms) for foreign nameservers. Packets with shorter RTT will be dropped.")
var minsafe = flag.Int("s", 100, "Minimum safe RTT (ms) for foreign nameservers. Packets with longer RTT will be accepted.")
var minwait = flag.Int("w", 50, "Only for trustworthy foreign servers. Time (ms) during which domestic answers are prioritized.")
var maxtime = flag.Int("M", 400, "Query timeout and foreign answers' maximum delay (ms). Use a larger value for DOH. (Max=2900)")
var maxdur = flag.Int("i", 50, "Maximum interval between spoofed answers (ms)")
var verbose = flag.Bool("v", false, "Verbose")
var showver = flag.Bool("V", false, "Show version")
var version = "unknown"
var builddate = "unknown"

type servertype int

const (
	domestic servertype = iota
	foreign
)

type nameserver struct {
	udpaddr *net.UDPAddr
	stype   servertype
}

type byByte []net.IPNet

func (n byByte) Len() int { return len(n) }
func (n byByte) Less(i, j int) bool {
	for b := 0; b < len(n[i].IP); b++ {
		if n[i].IP[b] < n[j].IP[b] {
			return true
		} else if n[i].IP[b] > n[j].IP[b] {
			return false
		}
	}
	return false
}
func (n byByte) Swap(i, j int) { n[i], n[j] = n[j], n[i] }

var (
	cnipnet4, cnipnet6   []net.IPNet
	blackips4, blackips6 []net.IPNet
	servers              []nameserver
	logger               = log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lmicroseconds)
	errlog               = log.New(os.Stderr, "", log.Ldate|log.Ltime|log.Lmicroseconds)
)

func parseservers(str string, stype servertype) (nss []nameserver) {
	servers := strings.Split(str, ",")
	for _, s := range servers {
		switch c := strings.Count(s, ":"); {
		case c == 0:
			s += ":53"
		case c > 1:
			if !strings.Contains(s, "]") {
				s = "[" + s + "]:53"
			} else if s[len(s)-1] == ']' {
				s += ":53"
			}
		}
		if addr, err := net.ResolveUDPAddr("udp", s); err != nil {
			errlog.Fatalf("Invalid nameserver %s: %v", s, err)
		} else {
			nss = append(nss, nameserver{udpaddr: addr, stype: stype})
			logger.Printf("Using nameserver %s", s)
		}
	}
	return
}

func parseiplist(filename string, iplen int) (ipnets []net.IPNet) {
	f, err := os.Open(filename)
	if err != nil {
		errlog.Fatalln(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		ipstr := scanner.Text()
		if !strings.Contains(ipstr, "/") {
			if strings.Contains(ipstr, ":") {
				ipstr += "/128"
			} else {
				ipstr += "/32"
			}
		}
		// ParseCIDR returns 16-byte net.IP and 4 or 16-byte net.IPNet (both IP and Mask)
		if _, ipnet, err := net.ParseCIDR(ipstr); err != nil {
			errlog.Fatalf("Invalid IP/CIDR: %s in file %s", scanner.Text(), filename)
		} else if len(ipnet.IP) == iplen {
			ipnets = append(ipnets, *ipnet)
		} else if iplen == net.IPv4len {
			errlog.Fatalf("IPv4 address needed: %s in file %s", scanner.Text(), filename)
		} else {
			errlog.Fatalf("IPv6 address needed: %s in file %s", scanner.Text(), filename)
		}
	}
	return
}

func cmpipipnet(ip net.IP, ipnet net.IPNet) int { // based on net.Contains()
	for i := 0; i < len(ip); i++ {
		if a, b := ip[i]&ipnet.Mask[i], ipnet.IP[i]&ipnet.Mask[i]; a < b {
			return -1
		} else if a > b {
			return 1
		}
	}
	return 0
}

func findipinnet(ip net.IP, ipnets []net.IPNet) bool { // based on sort.Search()
	for i, j := 0, len(ipnets); i < j; {
		switch k := int(uint(i+j) >> 1); cmpipipnet(ip, ipnets[k]) { // i <= k < j
		case -1:
			j = k
		case 0:
			return true
		case 1:
			i = k + 1
		}
	}
	return false
}

func addtag(bufs []bytes.Buffer, tag string) {
	for i := range bufs {
		fmt.Fprint(&bufs[i], tag)
	}
}

func handlequery(addr *net.UDPAddr, payload []byte, inconn *net.UDPConn) { // net.Addr is *net.UDPAddr, net.PacketConn is *net.UDPConn
	var p dnsmessage.Parser
	h, err := p.Start(payload)
	if err != nil {
		errlog.Println(err)
		return
	}
	var bufs []bytes.Buffer
	qs, err := p.AllQuestions()
	if err != nil {
		return
	}
	if *verbose {
		for _, q := range qs {
			var buf bytes.Buffer
			fmt.Fprintf(&buf, "%d %s Query[%s] %s len %d", h.ID, addr, q.Type.String()[4:], q.Name.String(), len(payload))
			bufs = append(bufs, buf)
		}
	}
	p.SkipAllAnswers()
	p.SkipAllAuthorities()
	dnssec := false
	rh, err := p.AdditionalHeader()
	if err == nil && rh.DNSSECAllowed() {
		dnssec = true
		if *verbose {
			addtag(bufs, " DNSSEC")
		}
	}
	if *verbose {
		for _, buf := range bufs {
			logger.Println(&buf)
		}
	}
	ch := make(chan []byte)
	chsave := make(chan []byte)
	go sendandreceive(payload, ch, chsave, qs[0].Type, dnssec)
	timer := time.After(3 * time.Second) // must be longer than query timeout, or goroutines may block
	answered := false
	var latestanswer []byte
	for {
		select {
		case a := <-ch:
			if !answered {
				if _, err := inconn.WriteTo(a, addr); err != nil {
					errlog.Println(err)
				}
				answered = true
			}
		case a := <-chsave:
			if !answered {
				latestanswer = a
			}
		case <-timer:
			if !answered && latestanswer != nil {
				if _, err := inconn.WriteTo(latestanswer, addr); err != nil {
					errlog.Println(err)
				}
			}
			return
		}
	}
}

func sendandreceive(payload []byte, ch, chsave chan<- []byte, qtype dnsmessage.Type, dnssec bool) {
	recvch := make([]chan []byte, len(servers))
	for i := range recvch {
		recvch[i] = make(chan []byte)
	}
	loc, _ := net.ResolveUDPAddr("udp", "")
	outconn, err := net.ListenUDP("udp", loc)
	if err != nil {
		errlog.Println(err)
		return
	}
	defer outconn.Close()
	for i, ns := range servers {
		if _, err := outconn.WriteTo(payload, ns.udpaddr); err != nil {
			continue
		}
		go parseanswer(ns, time.Now(), recvch[i], ch, chsave, dnssec, qtype)
	}
	outconn.SetReadDeadline(time.Now().Add(time.Duration(*maxtime) * time.Millisecond))
	for {
		payload := make([]byte, 1500)
		n, addr, err := outconn.ReadFromUDP(payload)
		if err != nil {
			break // receive timeout
		}
		if i, ok := lookupserver(addr); ok {
			recvch[i] <- payload[:n]
		} else {
			continue
		}
	}
	for _, ch := range recvch {
		close(ch)
	}
}

func lookupserver(addr *net.UDPAddr) (int, bool) {
	for i, s := range servers {
		if s.udpaddr.IP.Equal(addr.IP) {
			return i, true
		}
	}
	return 0, false
}

func parseanswer(ns nameserver, senttime time.Time, recvch <-chan []byte, ch, chsave chan<- []byte, dnssec bool, qtype dnsmessage.Type) {
	pcount := 0
	var firstrtt time.Duration
	answered := false
	for {
		a, ok := <-recvch
		if !ok {
			break // receive timeout
		}
		rtt := time.Since(senttime)
		toofast := false
		if ns.stype == foreign && rtt < time.Duration(*minrtt)*time.Millisecond {
			toofast = true
		}
		pcount++
		if pcount == 1 {
			firstrtt = rtt
		}
		var p dnsmessage.Parser
		h, err := p.Start(a)
		if err != nil {
			errlog.Println(err)
			continue
		}
		p.SkipAllQuestions()
		var geoerr, typeerr, hascname, hasa, hasaaaa, blacklisted, hasauth, dnssecerr bool
		acount := 0
		var bufs []bytes.Buffer
		for {
			// each loop for one answer
			ah, err := p.AnswerHeader()
			if err != nil {
				break
			}
			acount++
			var buf bytes.Buffer
			if *verbose {
				fmt.Fprintf(&buf, "%d %s Answer[%s]", h.ID, ns.udpaddr, ah.Type.String()[4:])
			}
			switch ah.Type {
			case dnsmessage.TypeA:
				hasa = true
				if cnipnet4 != nil || blackips4 != nil || *verbose {
					r, _ := p.AResource()
					ip := net.IP(r.A[:]) //r.A is 4-byte
					if *verbose {
						fmt.Fprintf(&buf, " %s %s len %d %dms", ah.Name.String(), ip.String(), len(a), rtt.Nanoseconds()/1000000)
					}
					if cnipnet4 != nil {
						iscn := findipinnet(ip, cnipnet4)
						if ns.stype == domestic && !iscn {
							geoerr = true
							if *verbose {
								fmt.Fprint(&buf, " GEOERR")
							}
						}
					}
					if blackips4 != nil {
						if findipinnet(ip, blackips4) {
							blacklisted = true
							if *verbose {
								fmt.Fprint(&buf, " BLACKLIST")
							}
						}
					}
				} else {
					p.SkipAnswer()
				}
				if qtype == dnsmessage.TypeAAAA {
					typeerr = true
					if *verbose {
						fmt.Fprint(&buf, " TYPEERR")
					}
				}
			case dnsmessage.TypeAAAA:
				hasaaaa = true
				if cnipnet6 != nil || blackips6 != nil || *verbose {
					r, _ := p.AAAAResource()
					ip := net.IP(r.AAAA[:])
					if *verbose {
						fmt.Fprintf(&buf, " %s %s len %d %dms", ah.Name.String(), ip.String(), len(a), rtt.Nanoseconds()/1000000)
					}
					if cnipnet6 != nil {
						iscn := findipinnet(ip, cnipnet6)
						if ns.stype == domestic && !iscn {
							geoerr = true
							if *verbose {
								fmt.Fprint(&buf, " GEOERR")
							}
						}
					}
					if blackips6 != nil {
						if findipinnet(ip, blackips6) {
							blacklisted = true
							if *verbose {
								fmt.Fprint(&buf, " BLACKLIST")
							}
						}
					}
				} else {
					p.SkipAnswer()
				}
			case dnsmessage.TypeCNAME:
				if *verbose {
					r, _ := p.CNAMEResource()
					fmt.Fprintf(&buf, " %s %s len %d %dms", ah.Name.String(), r.CNAME, len(a), rtt.Nanoseconds()/1000000)
				} else {
					p.SkipAnswer()
				}
				hascname = true
			case dnsmessage.TypePTR:
				if *verbose {
					r, _ := p.PTRResource()
					fmt.Fprintf(&buf, " %s %s len %d %dms", ah.Name.String(), r.PTR, len(a), rtt.Nanoseconds()/1000000)
				} else {
					p.SkipAnswer()
				}
			default:
				p.SkipAnswer()
			}
			if *verbose {
				if toofast {
					fmt.Fprint(&buf, " TOOFAST")
				}
				bufs = append(bufs, buf)
			}
		} // answer section parsed
		if _, err := p.Authority(); err == nil {
			hasauth = true
		}
		if dnssec && ns.stype == foreign {
			p.SkipAllAuthorities()
			if rh, err := p.AdditionalHeader(); err == nil && rh.DNSSECAllowed() {
				if *verbose {
					addtag(bufs, " DNSSEC")
				}
			} else {
				dnssecerr = true
				if *verbose {
					addtag(bufs, " NODNSSEC")
				}
			}
		}
		if !dnssecerr && !geoerr && !typeerr && !toofast && !blacklisted &&
			(h.RCode == dnsmessage.RCodeSuccess && qtype == dnsmessage.TypeA && hasa ||
				h.RCode == dnsmessage.RCodeSuccess && qtype == dnsmessage.TypeAAAA && (hasaaaa || hasauth) ||
				h.RCode == dnsmessage.RCodeSuccess && qtype != dnsmessage.TypeA && qtype != dnsmessage.TypeAAAA ||
				h.RCode == dnsmessage.RCodeNameError) {
			switch ns.stype {
			case domestic:
				if pcount == 1 {
					ch <- a
					answered = true
					if *verbose {
						addtag(bufs, " [ACCEPT]")
					}
				} else {
					if *verbose {
						addtag(bufs, " [IGNORE]")
					}
				}
			case foreign:
				if pcount == 1 {
					if qtype != dnsmessage.TypeA && qtype != dnsmessage.TypeAAAA ||
						rtt > time.Duration(*minsafe)*time.Millisecond || hascname || acount > 1 {
						if *trusted && rtt < time.Duration(*minwait)*time.Millisecond {
							time.Sleep(time.Duration(*minwait)*time.Millisecond - rtt)
							if *verbose {
								addtag(bufs, " [DELAYED]")
							}
						} else {
							if *verbose {
								addtag(bufs, " [ACCEPT]")
							}
						}
						ch <- a
						answered = true
					} else {
						if *verbose {
							addtag(bufs, " [SAVE]")
						}
						chsave <- a
					}
				} else {
					if rtt-firstrtt > time.Duration(*maxdur)*time.Millisecond || hascname || acount > 1 {
						if !answered {
							ch <- a
							answered = true
							if *verbose {
								addtag(bufs, " [ACCEPT]")
							}
						} else {
							if *verbose {
								addtag(bufs, " [IGNORE]")
							}
						}
					} else {
						if *verbose {
							addtag(bufs, " [SAVE]")
						}
						chsave <- a
					}
				}
			}
		} else {
			if *verbose {
				addtag(bufs, " [DROP]")
			}
		}
		if *verbose {
			for _, buf := range bufs {
				logger.Println(&buf)
			}
		}
		if answered && !*verbose {
			return
		}
	}
}

func main() {
	flag.Parse()
	if flag.NArg() > 0 || len(os.Args) == 1 {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}
	if *showver {
		fmt.Printf("shdns version %s (built %s)\n", version, builddate)
		return
	}
	if *ipnet4file != "" {
		cnipnet4 = parseiplist(*ipnet4file, net.IPv4len)
		if cnipnet4 != nil {
			logger.Printf("Loaded %d domestic IPv4 entries", len(cnipnet4))
			sort.Sort(byByte(cnipnet4))
		}
	}
	if cnipnet4 == nil {
		errlog.Fatalln("Domestic IPv4 list must be provided")
	}
	if *ipnet6file != "" {
		cnipnet6 = parseiplist(*ipnet6file, net.IPv6len)
		if cnipnet6 != nil {
			logger.Printf("Loaded %d domestic IPv6 entries", len(cnipnet6))
			sort.Sort(byByte(cnipnet6))
		}
	}
	if *blacklist4file != "" {
		blackips4 = parseiplist(*blacklist4file, net.IPv4len)
		if blackips4 != nil {
			logger.Printf("Loaded %d blacklisted IPv4 entries", len(blackips4))
		}
	}
	if *blacklist6file != "" {
		blackips6 = parseiplist(*blacklist6file, net.IPv6len)
		if blackips6 != nil {
			logger.Printf("Loaded %d blacklisted IPv6 entries", len(blackips6))
		}
	}
	servers = append(servers, parseservers(*dservers, domestic)...)
	servers = append(servers, parseservers(*fservers, foreign)...)
	if *trusted {
		logger.Print("Foreign servers in trustworthy mode")
		*minsafe = 0
		*minrtt = 0
	}
	loc, _ := net.ResolveUDPAddr("udp", *localnet)
	inconn, err := net.ListenUDP("udp", loc)
	if err != nil {
		errlog.Fatalln(err)
	}
	defer inconn.Close()
	logger.Printf("Listening on UDP %s", *localnet)
	for {
		payload := make([]byte, 1500)
		if n, addr, err := inconn.ReadFromUDP(payload); err != nil {
			errlog.Println(err)
			continue
		} else {
			go handlequery(addr, payload[:n], inconn)
		}
	}
}
