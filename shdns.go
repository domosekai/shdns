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
	"strconv"
	"strings"
	"time"
)

var localnet = flag.String("b", "localhost:5353", "Local binding address and UDP port (e.g. 127.0.0.1:5353 [::1]:5353)")
var dservers = flag.String("d", "114.114.114.114:53,223.5.5.5:53", "Domestic nameservers. Use format [IP]:port for IPv6.")
var fservers = flag.String("f", "8.8.8.8:53,1.1.1.1:53", "Foreign nameservers. Use format [IP]:port for IPv6.")
var trusted = flag.Bool("t", false, "Trustworthy mode. Foreign answers will not be checked for validity.")
var fast = flag.Bool("F", false, "Fast mode. Accept foreign IP from domestic nameservers if it passes basic checks.")
var ipnet4file = flag.String("l4", "", "Domestic IPv4 list file (one IP/CIDR each line) (Required)")
var ipnet6file = flag.String("l6", "", "Domestic IPv6 list file (one IP/CIDR each line)")
var blacklist4file = flag.String("k4", "", "IPv4 blacklist file for all nameservers (one IP/CIDR each line)")
var blacklist6file = flag.String("k6", "", "IPv6 blacklist file for all nameservers (one IP/CIDR each line)")
var minrtt = flag.Int("m", 30, "Minimum possible RTT (ms) for foreign nameservers. Packets with shorter RTT will be dropped.")
var minsafe = flag.Int("s", 100, "Minimum safe RTT (ms) for foreign nameservers. Packets with longer RTT will be accepted.")
var minwait = flag.Int("w", 50, "Only for trustworthy foreign servers. Time (ms) during which domestic answers are prioritized.")
var initimeout = flag.Int("T", 5, "Timeout (s) for the first reply from any server. Use a larger value for high latency network.")
var subtimeout = flag.Int("M", 1000, "Maximum delay (ms) allowed for subsequent replies from all servers. Use a larger value for DOH.")
var maxdur = flag.Int("i", 50, "Maximum interval between spoofed answers (ms)")
var verbose = flag.Bool("v", false, "Verbose mode. Connection will remain open after replied until timeout.")
var showver = flag.Bool("V", false, "Show version")
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
	cnIPNet4, cnIPNet6   []net.IPNet
	blackIPs4, blackIPs6 []net.IPNet
	servers              []nameserver
	logger               = log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lmicroseconds)
	errlog               = log.New(os.Stderr, "", log.Ldate|log.Ltime|log.Lmicroseconds)
)

func parseUDPAddr(str string) (*net.UDPAddr, error) {
	_, _, err := net.SplitHostPort(str)
	if err == nil {
		return net.ResolveUDPAddr("udp", str)
	}
	if _, _, err := net.SplitHostPort(str + ":53"); err == nil {
		return net.ResolveUDPAddr("udp", str+":53")
	}
	if _, _, err := net.SplitHostPort("[" + str + "]:53"); err == nil {
		return net.ResolveUDPAddr("udp", "["+str+"]:53")
	}
	return nil, err
}

func parseServers(str string, sType serverType) {
	serverstr := strings.Split(str, ",")
	for _, s := range serverstr {
		if addr, err := parseUDPAddr(s); err != nil {
			errlog.Fatalf("Invalid nameserver: %s", s)
		} else {
			if addr.Zone != "" {
				if zoneid, err := strconv.Atoi(addr.Zone); err == nil {
					if ifi, err := net.InterfaceByIndex(zoneid); err == nil {
						addr.Zone = ifi.Name
					} else {
						errlog.Fatalf("IPv6 zone invalid: %s", s)
					}
				} else if _, err := net.InterfaceByName(addr.Zone); err != nil {
					errlog.Fatalf("IPv6 zone invalid: %s", s)
				}
			}
			if _, exist := lookupServer(addr); !exist {
				servers = append(servers, nameserver{udpAddr: addr, sType: sType})
				logger.Printf("Using nameserver %s", addr)
			} else {
				errlog.Fatalf("Nameserver exists: %s", s)
			}
		}
	}
	return
}

func parseIPList(filename string, iplen int) (ipnets []net.IPNet) {
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

func cmpIPIPNet(ip net.IP, ipnet net.IPNet) int { // based on net.Contains()
	for i := 0; i < len(ip); i++ {
		if a, b := ip[i]&ipnet.Mask[i], ipnet.IP[i]&ipnet.Mask[i]; a < b {
			return -1
		} else if a > b {
			return 1
		}
	}
	return 0
}

func findIPInNet(ip net.IP, ipnets []net.IPNet) bool { // based on sort.Search()
	for i, j := 0, len(ipnets); i < j; {
		switch k := int(uint(i+j) >> 1); cmpIPIPNet(ip, ipnets[k]) { // i <= k < j
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

func addTag(bufs []bytes.Buffer, tag string) {
	for i := range bufs {
		fmt.Fprint(&bufs[i], tag)
	}
}

func handleQuery(addr *net.UDPAddr, payload []byte, inConn *net.UDPConn) { // net.Addr is *net.UDPAddr, net.PacketConn is *net.UDPConn
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
			fmt.Fprintf(&buf, "%d %s Query[%s] %s len %d", h.ID, addr, strings.TrimPrefix(q.Type.String(), "Type"), q.Name.String(), len(payload))
			bufs = append(bufs, buf)
		}
	}
	p.SkipAllAnswers()
	p.SkipAllAuthorities()
	dnssec := false
	hasOPT := false
	for {
		rh, err := p.AdditionalHeader()
		if err != nil {
			break
		}
		if rh.Type == dnsmessage.TypeOPT {
			hasOPT = true
			if rh.DNSSECAllowed() {
				dnssec = true
			}
		}
		p.SkipAdditional()
	}
	if *verbose {
		if hasOPT {
			addTag(bufs, " OPT")
		}
		if dnssec {
			addTag(bufs, " DNSSEC")
		}
		for _, buf := range bufs {
			logger.Println(&buf)
		}
	}
	chAnswer := make(chan []byte)
	chSave := make(chan []byte)
	loc, _ := net.ResolveUDPAddr("udp", "")
	outConn, err := net.ListenUDP("udp", loc)
	if err != nil {
		errlog.Println(err)
		return
	}
	defer outConn.Close()
	go forwardQuery(payload, outConn, chAnswer, chSave, qs[0].Type, hasOPT, dnssec)
	answered := false
	var lastAnswer []byte
	for {
		select {
		case a, ok := <-chAnswer:
			if ok {
				// receive answer from goroutines
				if !answered {
					if _, err := inConn.WriteToUDP(a, addr); err != nil {
						errlog.Println(err)
					}
					answered = true
					if !*verbose {
						outConn.Close()
					}
				}
			} else {
				if !answered && lastAnswer != nil {
					if _, err := inConn.WriteToUDP(lastAnswer, addr); err != nil {
						errlog.Println(err)
					}
				}
				if *verbose {
					logger.Printf("%d Connection closed", h.ID)
				}
				return
			}
		case a := <-chSave:
			if !answered {
				lastAnswer = a
			}
		}
	}
}

func forwardQuery(payload []byte, outConn *net.UDPConn, chAnswer, chSave chan<- []byte, qType dnsmessage.Type, hasOPT, dnssec bool) {
	defer close(chAnswer)
	chRecv := make([]chan []byte, len(servers))
	chDone := make([]chan bool, len(servers))
	sentTime := time.Now()
	for i, ns := range servers {
		if _, err := outConn.WriteToUDP(payload, ns.udpAddr); err != nil {
			continue
		}
		chRecv[i] = make(chan []byte)
		chDone[i] = make(chan bool)
		go parseAnswer(ns, sentTime, chRecv[i], chAnswer, chSave, chDone[i], qType, hasOPT, dnssec)
		defer func(chRecv chan []byte, chDone chan bool) {
			close(chRecv)
			<-chDone
		}(chRecv[i], chDone[i])
	}
	outConn.SetReadDeadline(sentTime.Add(time.Duration(*initimeout) * time.Second))
	received := false
	for {
		payload := make([]byte, 5000)
		// receive from nameserver
		n, addr, err := outConn.ReadFromUDP(payload)
		if err != nil {
			return
		}
		if !received {
			received = true
			outConn.SetReadDeadline(time.Now().Add(time.Duration(*subtimeout) * time.Millisecond))
		}
		// forward to each goroutine
		if i, ok := lookupServer(addr); ok {
			chRecv[i] <- payload[:n]
		}
	}
}

func lookupServer(addr *net.UDPAddr) (int, bool) {
	for i, s := range servers {
		if s.udpAddr.IP.Equal(addr.IP) && s.udpAddr.Port == addr.Port && s.udpAddr.Zone == addr.Zone {
			return i, true
		}
	}
	return 0, false
}

func parseAnswer(ns nameserver, sentTime time.Time, chRecv <-chan []byte, chAnswer, chSave chan<- []byte, chDone chan<- bool, qType dnsmessage.Type, hasOPT, dnssec bool) {
	pktCount := 0
	var firstRTT time.Duration
	answered := false
	for {
		a, ok := <-chRecv
		if !ok {
			chDone <- true
			return // receive channel closed
		}
		rtt := time.Since(sentTime)
		tooFast := false
		if ns.sType == foreign && rtt < time.Duration(*minrtt)*time.Millisecond {
			tooFast = true
		}
		pktCount++
		if pktCount == 1 {
			firstRTT = rtt
		}
		var p dnsmessage.Parser
		h, err := p.Start(a)
		if err != nil {
			errlog.Println(err)
			continue
		}
		p.SkipAllQuestions()
		var geoErr, typeErr, hasCNAME, hasA, hasAAAA, inBlacklist, dnssecErr, optErr bool
		ansCount := 0
		var bufs []bytes.Buffer
		for {
			// each loop parses one answer from a reply packet
			ah, err := p.AnswerHeader()
			if err != nil {
				break
			}
			ansCount++
			var buf bytes.Buffer
			if *verbose {
				fmt.Fprintf(&buf, "%d %s Answer[%s]", h.ID, ns.udpAddr, strings.TrimPrefix(ah.Type.String(), "Type"))
			}
			switch ah.Type {
			case dnsmessage.TypeA:
				hasA = true
				if cnIPNet4 != nil || blackIPs4 != nil || *verbose {
					r, _ := p.AResource()
					ip := net.IP(r.A[:]) //r.A is 4-byte
					if *verbose {
						fmt.Fprintf(&buf, " %s %s len %d %dms", ah.Name.String(), ip.String(), len(a), rtt.Nanoseconds()/1000000)
					}
					if ns.sType == domestic && cnIPNet4 != nil {
						if !findIPInNet(ip, cnIPNet4) {
							geoErr = true
							if *verbose {
								fmt.Fprint(&buf, " GEOERR")
							}
						}
					}
					if blackIPs4 != nil {
						if findIPInNet(ip, blackIPs4) {
							inBlacklist = true
							if *verbose {
								fmt.Fprint(&buf, " BLACKLIST")
							}
						}
					}
				} else {
					p.SkipAnswer()
				}
				if qType == dnsmessage.TypeAAAA {
					typeErr = true
					if *verbose {
						fmt.Fprint(&buf, " TYPEERR")
					}
				}
			case dnsmessage.TypeAAAA:
				hasAAAA = true
				if cnIPNet6 != nil || blackIPs6 != nil || *verbose {
					r, _ := p.AAAAResource()
					ip := net.IP(r.AAAA[:])
					if *verbose {
						fmt.Fprintf(&buf, " %s %s len %d %dms", ah.Name.String(), ip.String(), len(a), rtt.Nanoseconds()/1000000)
					}
					if ns.sType == domestic && cnIPNet6 != nil {
						if !findIPInNet(ip, cnIPNet6) {
							geoErr = true
							if *verbose {
								fmt.Fprint(&buf, " GEOERR")
							}
						}
					}
					if blackIPs6 != nil {
						if findIPInNet(ip, blackIPs6) {
							inBlacklist = true
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
				hasCNAME = true
			case dnsmessage.TypePTR:
				if *verbose {
					r, _ := p.PTRResource()
					fmt.Fprintf(&buf, " %s %s len %d %dms", ah.Name.String(), r.PTR, len(a), rtt.Nanoseconds()/1000000)
				} else {
					p.SkipAnswer()
				}
			default:
				if *verbose {
					fmt.Fprintf(&buf, " %s len %d %dms", ah.Name.String(), len(a), rtt.Nanoseconds()/1000000)
				}
				p.SkipAnswer()
			}
			if *verbose {
				if tooFast {
					fmt.Fprint(&buf, " TOOFAST")
				}
				bufs = append(bufs, buf)
			}
		} // answer section parsed
		if *verbose && ansCount == 0 {
			var buf bytes.Buffer
			fmt.Fprintf(&buf, "%d %s Answer[Empty] len %d %dms", h.ID, ns.udpAddr, len(a), rtt.Nanoseconds()/1000000)
			bufs = append(bufs, buf)
		}
		authCount := 0
		for {
			if _, err := p.AuthorityHeader(); err != nil {
				break
			}
			authCount++
			p.SkipAuthority()
		}
		addtCount := 0
		dnssecErr = dnssec && (ns.sType == foreign || qType != dnsmessage.TypeA && qType != dnsmessage.TypeAAAA)
		optErr = hasOPT
		for {
			rh, err := p.AdditionalHeader()
			if err != nil {
				break
			}
			addtCount++
			switch rh.Type {
			case dnsmessage.TypeA, dnsmessage.TypeAAAA:
				optErr = true
			case dnsmessage.TypeOPT:
				optErr = false
				// ISP nameservers most likely cannot hold DNSSEC query
				if ns.sType == foreign || qType != dnsmessage.TypeA && qType != dnsmessage.TypeAAAA {
					if dnssec == rh.DNSSECAllowed() {
						dnssecErr = false
					} else {
						dnssecErr = true
					}
				}
			}
			p.SkipAdditional()
		}
		if *verbose {
			if optErr {
				addTag(bufs, " OPTERR")
			}
			if dnssecErr {
				addTag(bufs, " DNSSECERR")
			}
			if h.RCode != dnsmessage.RCodeSuccess {
				addTag(bufs, " "+h.RCode.String())
			}
			addTag(bufs, " "+strconv.Itoa(ansCount)+"/"+strconv.Itoa(authCount)+"/"+strconv.Itoa(addtCount))
		}
		if !dnssecErr && (!geoErr || *fast && ansCount > 1) && !typeErr && !optErr && !tooFast && !inBlacklist &&
			(h.RCode == dnsmessage.RCodeSuccess && qType == dnsmessage.TypeA && hasA ||
				h.RCode == dnsmessage.RCodeSuccess && qType == dnsmessage.TypeAAAA && (hasAAAA || hasCNAME || authCount > 0) ||
				h.RCode == dnsmessage.RCodeSuccess && qType != dnsmessage.TypeA && qType != dnsmessage.TypeAAAA ||
				h.RCode == dnsmessage.RCodeNameError) ||
			ns.sType == foreign && *trusted {
			switch ns.sType {
			case domestic:
				if pktCount == 1 {
					chAnswer <- a
					answered = true
					if *verbose {
						addTag(bufs, " [ACCEPT]")
					}
				} else {
					if *verbose {
						addTag(bufs, " [IGNORE]")
					}
				}
			case foreign:
				if pktCount == 1 {
					// first reply from this server
					if qType != dnsmessage.TypeA && qType != dnsmessage.TypeAAAA ||
						rtt > time.Duration(*minsafe)*time.Millisecond || hasCNAME || ansCount > 1 {
						if *trusted && rtt < time.Duration(*minwait)*time.Millisecond {
							time.Sleep(time.Duration(*minwait)*time.Millisecond - rtt)
							if *verbose {
								addTag(bufs, " [WAIT FOR DOMESTIC]")
							}
						} else {
							if *verbose {
								addTag(bufs, " [ACCEPT]")
							}
						}
						chAnswer <- a
						answered = true
					} else {
						time.Sleep(time.Duration(*minsafe)*time.Millisecond - rtt)
						if *verbose {
							addTag(bufs, " [WAIT UNTIL SAFE]")
						}
						chAnswer <- a
						answered = true
					}
				} else {
					if rtt-firstRTT > time.Duration(*maxdur)*time.Millisecond || hasCNAME || ansCount > 1 {
						if !answered {
							chAnswer <- a
							answered = true
							if *verbose {
								addTag(bufs, " [ACCEPT]")
							}
						} else {
							if *verbose {
								addTag(bufs, " [IGNORE]")
							}
						}
					} else {
						if *verbose {
							addTag(bufs, " [SAVE]")
						}
						chSave <- a
					}
				}
			}
		} else {
			if *verbose {
				addTag(bufs, " [DROP]")
			}
		}
		if *verbose {
			for _, buf := range bufs {
				logger.Println(&buf)
			}
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
		cnIPNet4 = parseIPList(*ipnet4file, net.IPv4len)
		if cnIPNet4 != nil {
			logger.Printf("Loaded %d domestic IPv4 entries", len(cnIPNet4))
			sort.Sort(byByte(cnIPNet4))
		}
	}
	if cnIPNet4 == nil {
		errlog.Fatalln("Domestic IPv4 list must be provided")
	}
	if *ipnet6file != "" {
		cnIPNet6 = parseIPList(*ipnet6file, net.IPv6len)
		if cnIPNet6 != nil {
			logger.Printf("Loaded %d domestic IPv6 entries", len(cnIPNet6))
			sort.Sort(byByte(cnIPNet6))
		}
	}
	if *blacklist4file != "" {
		blackIPs4 = parseIPList(*blacklist4file, net.IPv4len)
		if blackIPs4 != nil {
			logger.Printf("Loaded %d blacklisted IPv4 entries", len(blackIPs4))
		}
	}
	if *blacklist6file != "" {
		blackIPs6 = parseIPList(*blacklist6file, net.IPv6len)
		if blackIPs6 != nil {
			logger.Printf("Loaded %d blacklisted IPv6 entries", len(blackIPs6))
		}
	}
	parseServers(*dservers, domestic)
	parseServers(*fservers, foreign)
	if *trusted {
		logger.Print("Foreign servers in trustworthy mode")
		*minsafe = 0
		*minrtt = 0
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
	for {
		payload := make([]byte, 1500)
		if n, addr, err := inConn.ReadFromUDP(payload); err != nil {
			errlog.Println(err)
			continue
		} else {
			go handleQuery(addr, payload[:n], inConn)
		}
	}
}
