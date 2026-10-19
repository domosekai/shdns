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
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"shdns/dnsmessage"
)

func lookupServer(addr *net.UDPAddr) (nameserver, bool) {
	return lookupServerIn(addr, servers)
}

func lookupServerIn(addr *net.UDPAddr, list []nameserver) (nameserver, bool) {
	for _, s := range list {
		if s.udpAddr.IP.Equal(addr.IP) && s.udpAddr.Port == addr.Port && s.udpAddr.Zone == addr.Zone {
			return s, true
		}
	}
	return nameserver{}, false
}

func checkIPGeo(ip net.IP, sType serverType, isIPv6 bool) bool {
	if sType != domestic {
		return false
	}
	if isIPv6 {
		return cnIPNet6 != nil && !findIPInNet(ip, cnIPNet6)
	}
	return cnIPNet4 != nil && !findIPInNet(ip, cnIPNet4)
}

func checkIPBlacklist(ip net.IP, isIPv6 bool) bool {
	if isIPv6 {
		return blackIPs6 != nil && findIPInNet(ip, blackIPs6)
	}
	return blackIPs4 != nil && findIPInNet(ip, blackIPs4)
}

func handleQuery(addr *net.UDPAddr, payload []byte, inConn *net.UDPConn) {
	var p dnsmessage.Parser
	h, err := p.Start(payload)
	if err != nil {
		errlog.Println(err)
		return
	}
	var bufs []bytes.Buffer
	qs, err := p.AllQuestions()
	if err != nil || len(qs) == 0 {
		return
	}
	if *verbose {
		for _, q := range qs {
			var buf bytes.Buffer
			fmt.Fprintf(&buf, "%d %s Query[%s] %s len %d", h.ID, addr, strings.TrimPrefix(q.Type.String(), "Type"), q.Name.String(), len(payload))
			bufs = append(bufs, buf)
		}
	}
	if p.SkipAllAnswers() != nil || p.SkipAllAuthorities() != nil {
		return
	}
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
		if p.SkipAdditional() != nil {
			return
		}
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
	chAnswer := make(chan answer)
	chSave := make(chan answer)
	chFail := make(chan []byte)
	loc, _ := net.ResolveUDPAddr("udp", "")
	outConn, err := net.ListenUDP("udp", loc)
	if err != nil {
		errlog.Println(err)
		return
	}
	defer outConn.Close()
	go forwardQueryAndReply(payload, outConn, chAnswer, chSave, chFail, qs[0].Type, hasOPT, dnssec)
	qName := qs[0].Name.String()
	answered := false
	waiting := true
	var savedAnswer, waitedAnswer answer
	var failedAnswer []byte
	timerSafe := time.NewTimer(time.Duration(*minsafe) * time.Millisecond)
	timerWait := time.NewTimer(time.Duration(*minwait) * time.Millisecond)
	for {
		select {
		case a, ok := <-chAnswer:
			if ok {
				if !answered {
					if a.sType == domestic && a.payload == nil {
						waiting = false
						if waitedAnswer.payload != nil {
							addIPsToSet(waitedAnswer.ips, qName, h.ID)
							sendAnswer(inConn, addr, waitedAnswer, qName)
							answered = true
						}
					} else if a.sType == domestic || !waiting || qs[0].Type != dnsmessage.TypeA && qs[0].Type != dnsmessage.TypeAAAA && qs[0].Type != dnsmessage.TypeHTTPS {
						// assume domestic nameservers can handle A, AAAA and HTTPS properly
						addIPsToSet(a.ips, qName, h.ID)
						sendAnswer(inConn, addr, a, qName)
						answered = true
					} else if waitedAnswer.payload == nil {
						waitedAnswer = a
					}
				}
			} else {
				// chAnswer is closed
				if !answered {
					if failedAnswer != nil {
						if _, err := inConn.WriteToUDP(failedAnswer, addr); err != nil {
							errlog.Println(err)
						}
					} else {
						// warn user that no answer is returned
						q := qs[0]
						errlog.Printf("%d Timeout for Query[%s] %s", h.ID, strings.TrimPrefix(q.Type.String(), "Type"), q.Name.String())
					}
				}
				if *verbose {
					logger.Printf("%d Connection closed", h.ID)
				}
				return
			}
		case <-timerWait.C:
			waiting = false
			if !answered && waitedAnswer.payload != nil {
				addIPsToSet(waitedAnswer.ips, qName, h.ID)
				sendAnswer(inConn, addr, waitedAnswer, qName)
				answered = true
			}
		case <-timerSafe.C:
			if !answered && savedAnswer.payload != nil {
				addIPsToSet(savedAnswer.ips, qName, h.ID)
				sendAnswer(inConn, addr, savedAnswer, qName)
				answered = true
			}
		case a := <-chSave:
			if !answered {
				savedAnswer = a
			}
		case a := <-chFail:
			if !answered {
				failedAnswer = a
			}
		}
	}
}

func cacheReverse(a answer, qName string) {
	if *reversenet == "" || len(a.ips) == 0 {
		return
	}
	reverse := make(map[string]string, len(a.ips))
	for _, ip := range a.ips {
		reverse[ip.String()] = qName
	}
	reverseTable.insert(reverse, a.ns)
}

func sendAnswer(inConn *net.UDPConn, addr *net.UDPAddr, a answer, qName string) {
	if _, err := inConn.WriteToUDP(a.payload, addr); err != nil {
		errlog.Println(err)
		return
	}
	cacheReverse(a, qName)
}

func forwardQueryAndReply(payload []byte, outConn *net.UDPConn, chAnswer, chSave chan<- answer, chFail chan<- []byte, qType dnsmessage.Type, hasOPT, dnssec bool) {
	defer close(chAnswer)
	sentTime := time.Now()
	for _, ns := range servers {
		outConn.WriteToUDP(payload, ns.udpAddr)
	}
	outConn.SetReadDeadline(sentTime.Add(time.Duration(*timeout) * time.Millisecond))
	parseAnswers(outConn, sentTime, chAnswer, chSave, chFail, qType, hasOPT, dnssec)
}

func parseAnswers(conn *net.UDPConn, sentTime time.Time, chAnswer, chSave chan<- answer, chFail chan<- []byte, qType dnsmessage.Type, hasOPT, dnssec bool) {
	for {
		var payload [5000]byte
		// receive from nameserver
		n, addr, err := conn.ReadFromUDP(payload[:])
		if err != nil {
			// out connection either timeout or closed
			return
		}
		// match nameserver
		ns, ok := lookupServer(addr)
		if !ok {
			continue
		}
		// start parsing
		a := payload[:n]
		rtt := time.Since(sentTime)
		tooFast := false
		if ns.sType == foreign && rtt < time.Duration(*minrtt)*time.Millisecond {
			tooFast = true
		}
		var p dnsmessage.Parser
		h, err := p.Start(a)
		if err != nil {
			errlog.Println(err)
			continue
		}
		if !h.Response || h.Truncated {
			continue
		}
		if p.SkipAllQuestions() != nil {
			continue
		}
		var geoErr, typeErr, hasCNAME, hasA, hasAAAA, hasHTTPS, inBlacklist, dnssecErr, optErr, invalidResponse bool
		ansCount := 0
		var bufs []bytes.Buffer
		var ips []net.IP
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
				if cnIPNet4 != nil || blackIPs4 != nil || *verbose || *reversenet != "" {
					r, err := p.AResource()
					if err != nil {
						invalidResponse = true
						break
					}
					ip := net.IP(r.A[:]) //r.A is 4-byte
					if len(ipsetSpecs) > 0 || len(nftSetSpecs) > 0 || *reversenet != "" {
						ips = append(ips, ip)
					}
					if *verbose {
						fmt.Fprintf(&buf, " %s %s len %d %dms", ah.Name.String(), ip.String(), len(a), rtt.Nanoseconds()/1000000)
					}
					if checkIPGeo(ip, ns.sType, false) {
						geoErr = true
						if *verbose {
							fmt.Fprint(&buf, " GEOERR")
						}
					}
					if checkIPBlacklist(ip, false) {
						inBlacklist = true
						if *verbose {
							fmt.Fprint(&buf, " BLACKLIST")
						}
					}
				} else {
					if p.SkipAnswer() != nil {
						invalidResponse = true
						break
					}
				}
				if qType == dnsmessage.TypeAAAA || qType == dnsmessage.TypeHTTPS {
					typeErr = true
					if *verbose {
						fmt.Fprint(&buf, " TYPEERR")
					}
				}
			case dnsmessage.TypeAAAA:
				hasAAAA = true
				if cnIPNet6 != nil || blackIPs6 != nil || *verbose || *reversenet != "" {
					r, err := p.AAAAResource()
					if err != nil {
						invalidResponse = true
						break
					}
					ip := net.IP(r.AAAA[:])
					if len(ipsetSpecs) > 0 || len(nftSetSpecs) > 0 || *reversenet != "" {
						ips = append(ips, ip)
					}
					if *verbose {
						fmt.Fprintf(&buf, " %s %s len %d %dms", ah.Name.String(), ip.String(), len(a), rtt.Nanoseconds()/1000000)
					}
					if checkIPGeo(ip, ns.sType, true) {
						geoErr = true
						if *verbose {
							fmt.Fprint(&buf, " GEOERR")
						}
					}
					if checkIPBlacklist(ip, true) {
						inBlacklist = true
						if *verbose {
							fmt.Fprint(&buf, " BLACKLIST")
						}
					}
				} else {
					if p.SkipAnswer() != nil {
						invalidResponse = true
						break
					}
				}
			case dnsmessage.TypeCNAME:
				if *verbose {
					r, err := p.CNAMEResource()
					if err != nil {
						invalidResponse = true
						break
					}
					fmt.Fprintf(&buf, " %s %s len %d %dms", ah.Name.String(), r.CNAME, len(a), rtt.Nanoseconds()/1000000)
				} else {
					if p.SkipAnswer() != nil {
						invalidResponse = true
						break
					}
				}
				hasCNAME = true
			case dnsmessage.TypePTR:
				if *verbose {
					r, err := p.PTRResource()
					if err != nil {
						invalidResponse = true
						break
					}
					fmt.Fprintf(&buf, " %s %s len %d %dms", ah.Name.String(), r.PTR, len(a), rtt.Nanoseconds()/1000000)
				} else {
					if p.SkipAnswer() != nil {
						invalidResponse = true
						break
					}
				}
			case dnsmessage.TypeTXT:
				if *verbose {
					r, err := p.TXTResource()
					if err != nil {
						invalidResponse = true
						break
					}
					fmt.Fprintf(&buf, " %s %s len %d %dms", ah.Name.String(), r.TXT, len(a), rtt.Nanoseconds()/1000000)
				} else {
					if p.SkipAnswer() != nil {
						invalidResponse = true
						break
					}
				}
			case dnsmessage.TypeSRV:
				if *verbose {
					r, err := p.SRVResource()
					if err != nil {
						invalidResponse = true
						break
					}
					fmt.Fprintf(&buf, " %s %d %d %d %s len %d %dms", ah.Name.String(), r.Priority, r.Weight, r.Port, r.Target, len(a), rtt.Nanoseconds()/1000000)
				} else {
					if p.SkipAnswer() != nil {
						invalidResponse = true
						break
					}
				}
			case dnsmessage.TypeHTTPS:
				hasHTTPS = true
				r, err := p.HTTPSResource()
				if err != nil {
					invalidResponse = true
					break
				}
				if *verbose {
					fmt.Fprintf(&buf, " %s %d %s", ah.Name.String(), r.Priority, r.Target)
					if r.ALPN != nil {
						fmt.Fprintf(&buf, " alpn %s", r.ALPN)
					}
					if r.Port != 0 {
						fmt.Fprintf(&buf, " port %d", r.Port)
					}
				}
				if r.IPv4Hint != nil {
					for i := range r.IPv4Hint {
						ip := net.IP(r.IPv4Hint[i][:])
						if *verbose {
							fmt.Fprintf(&buf, " %s", ip.String())
						}
						if len(ipsetSpecs) > 0 || len(nftSetSpecs) > 0 || *reversenet != "" {
							ips = append(ips, ip)
						}
						if checkIPGeo(ip, ns.sType, false) {
							geoErr = true
							if *verbose {
								fmt.Fprint(&buf, " GEOERR")
							}
						}
						if checkIPBlacklist(ip, false) {
							inBlacklist = true
							if *verbose {
								fmt.Fprint(&buf, " BLACKLIST")
							}
						}
					}
				}
				if r.IPv6Hint != nil {
					for i := range r.IPv6Hint {
						ip := net.IP(r.IPv6Hint[i][:])
						if *verbose {
							fmt.Fprintf(&buf, " %s", ip.String())
						}
						if len(ipsetSpecs) > 0 || len(nftSetSpecs) > 0 || *reversenet != "" {
							ips = append(ips, ip)
						}
						if checkIPGeo(ip, ns.sType, true) {
							geoErr = true
							if *verbose {
								fmt.Fprint(&buf, " GEOERR")
							}
						}
						if checkIPBlacklist(ip, true) {
							inBlacklist = true
							if *verbose {
								fmt.Fprint(&buf, " BLACKLIST")
							}
						}
					}
				}
				if *verbose {
					fmt.Fprintf(&buf, " len %d %dms", len(a), rtt.Nanoseconds()/1000000)
				}
			default:
				if *verbose {
					fmt.Fprintf(&buf, " %s len %d %dms", ah.Name.String(), len(a), rtt.Nanoseconds()/1000000)
				}
				if p.SkipAnswer() != nil {
					invalidResponse = true
				}
			}
			if invalidResponse {
				break
			}
			if *verbose {
				if tooFast {
					fmt.Fprint(&buf, " TOOFAST")
				}
				bufs = append(bufs, buf)
			}
		} // answer section parsed
		if invalidResponse {
			continue
		}
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
			if p.SkipAuthority() != nil {
				invalidResponse = true
				break
			}
		}
		if invalidResponse {
			continue
		}
		addtCount := 0
		dnssecErr = dnssec && (ns.sType == foreign || qType != dnsmessage.TypeA && qType != dnsmessage.TypeAAAA && qType != dnsmessage.TypeHTTPS)
		optErr = hasOPT && (ns.sType == foreign || qType != dnsmessage.TypeA && qType != dnsmessage.TypeAAAA && qType != dnsmessage.TypeHTTPS)
		for {
			rh, err := p.AdditionalHeader()
			if err != nil {
				break
			}
			addtCount++
			switch rh.Type {
			case dnsmessage.TypeOPT:
				optErr = false
				// ISP nameservers most likely cannot hold DNSSEC query
				if ns.sType == foreign || qType != dnsmessage.TypeA && qType != dnsmessage.TypeAAAA && qType != dnsmessage.TypeHTTPS {
					if dnssec == rh.DNSSECAllowed() {
						dnssecErr = false
					} else {
						dnssecErr = true
					}
				}
			}
			if p.SkipAdditional() != nil {
				invalidResponse = true
				break
			}
		}
		if invalidResponse {
			continue
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
		if ns.sType == foreign && *trusted || !dnssecErr && (!geoErr || *fast && ansCount > 1) && !typeErr && !optErr && !tooFast && !inBlacklist &&
			(h.RCode == dnsmessage.RCodeSuccess && qType == dnsmessage.TypeA && (hasA || ns.sType == foreign) ||
				h.RCode == dnsmessage.RCodeSuccess && qType == dnsmessage.TypeAAAA && (hasAAAA || authCount > 0 || ns.sType == foreign) ||
				h.RCode == dnsmessage.RCodeSuccess && qType == dnsmessage.TypeHTTPS && (hasHTTPS || authCount > 0 || ns.sType == foreign) ||
				h.RCode == dnsmessage.RCodeSuccess && qType != dnsmessage.TypeA && qType != dnsmessage.TypeAAAA && qType != dnsmessage.TypeHTTPS && ns.sType == foreign ||
				h.RCode == dnsmessage.RCodeNameError && ns.sType == foreign) {
			switch ns.sType {
			case domestic:
				if *verbose {
					addTag(bufs, " [ACCEPT]")
				}
				chAnswer <- answer{a, domestic, ips, ns.udpAddr.String()}
			case foreign:
				if qType != dnsmessage.TypeA && qType != dnsmessage.TypeAAAA && qType != dnsmessage.TypeHTTPS ||
					rtt > time.Duration(*minsafe)*time.Millisecond || hasCNAME || ansCount > 1 {
					if *verbose {
						addTag(bufs, " [ACCEPT]")
					}
					chAnswer <- answer{a, foreign, ips, ns.udpAddr.String()}
				} else {
					if *verbose {
						addTag(bufs, " [SAVE]")
					}
					chSave <- answer{a, foreign, ips, ns.udpAddr.String()}
				}
			}
		} else if h.RCode == dnsmessage.RCodeServerFailure && ns.sType == foreign {
			if *verbose {
				addTag(bufs, " [SAVE]")
			}
			chFail <- a
		} else {
			// send empty answer to signal that domestic has replied
			if ns.sType == domestic {
				chAnswer <- answer{nil, domestic, nil, ""}
			}
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
