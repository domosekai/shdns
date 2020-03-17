# shdns
A port of ChinaDNS in go with IPv6 support.

[ChinaDNS] by clowwindy has long been chosen by many internet users in China as their primary weapon to filter spoofed DNS responses. It is lightweight, non-caching, and friendly to domestic CDN. 

However, last committed in 2015, ChinaDNS has several areas that can be improved.

Issues of ChinaDNS
----
* No IPv6 filter

  IPv6 (AAAA) answers are always accepted. Given the widespread IPv6 environment in China, the feature becomes increasingly necessary.

* Fixed outbound port

  The program uses a fixed UDP port for all outbound queries. This not only makes the behavior easy to identify and also brings difficulties to programming. For example, ChinaDNS has to maintain and manipulate query IDs (to deal with duplicate IDs) so that it could link responses to queries.

* Not friendly to local caching server

  ChinaDNS assumes foreign servers have higher latencies than domestic ones. Therefore, if a local caching DNS proxy (e.g. dnscrypt-proxy) is used as the foreign server, it could respond faster than domestic servers which may lead to CDN issues. As non-VPN solutions (e.g. DNS over socks/tls/https) have become the go-to choice of mainstream users, using ChinaDNS with non-caching servers negatively impacts efficiency. (For example, the popular Koolshare project provides ChinaDNS option which pairs ChinaDNS with non-caching dns2socks as upstream.)

* Lack of flexibility in tuning parameters

  The only parameter a user can tweak is the duration of the delay. 

* Simple verbose mode

  Actions (filter, pass, delay) are shown but reasons are not given.

Similar projects
----
* [overture]: very rich expansion with support of IPv6, cache, domain filter, TTL manipulation, edns-client-subnet, socks, dns-ver-tls etc.

* [freedns-go]

* [yadd]

* [ChinaDNS 2]: master branch contains minor improvements to the original ChinaDNS and ecs branch is so-called ChinaDNS 2 which supports edns-client-subnet

Idea of shdns
----
shdns starts a new goroutine for each incoming query. The goroutine creates a new port and forwards the query to each server without modification. Answers received are naturally linked with the original query and are checked in the following regards.

* Type mismatch
  
  Such as when an AAAA query is sent but an A response is returned, or a DNSSEC-enabled query gets a DNSSEC-disabled response.

* Bad status

  Such as when an A query is sent, and the status of response is NOERROR but no A record is returned.

* RTT (disabled in trustworthy mode)

  Answers from foreign servers earlier than some threshold (`-m`) are unlikely to be genuine.

  Assuming the spoofed answers should return at about the same time (`-i`), then subsequent answers out of the interval are considered real.
  
* Geographic filter

  Foreign IPs (including IPv6 if IPv6 list is provided) returned by domestic servers are dropped. Answers from foreign servers are not filtered.
  
* Blacklist filter

  Useful if your ISP returns special IPs for non-existent or blocked domains. Applied to all nameservers.

I very much appreciate the simple idea behind ChinaDNS and believe many functions are better delegated to well-known and more mature alternatives. The main purpose of shdns is to fix the above issues of ChinaDNS rather than enrich it. Therefore, the following features are not available, at least for the time being.

* DNS over TCP/SOCKS/TLS/HTTPS: Use a local proxy (e.g. dnscrypt-proxy) supporting these as shdns's upstream.

* Caching: Same above.

* Domain filter: Use dnsmasq or overture.

Parameters
----
    -F  Fast mode. Accept foreign IP from domestic nameservers if it passes basic checks.
    -M int
        Maximum delay (ms) allowed for subsequent replies from all servers. Use a larger value for DOH. (default 1000)
    -T int
        Timeout (s) for the first reply from any server. Use a larger value for high latency network. (default 5)
    -V  Show version
    -b string
        Local binding address and UDP port (e.g. 127.0.0.1:5353 [::1]:5353) (default "localhost:5353")
    -d string
        Domestic nameservers. Use format [IP]:port for IPv6. (default "114.114.114.114:53,223.5.5.5:53")
    -f string
        Foreign nameservers. Use format [IP]:port for IPv6. (default "8.8.8.8:53,1.1.1.1:53")
    -i int
        Maximum interval between spoofed answers (ms) (default 50)
    -k4 string
        IPv4 blacklist file for all nameservers (one IP/CIDR each line)
    -k6 string
        IPv6 blacklist file for all nameservers (one IP/CIDR each line)
    -l4 string
        Domestic IPv4 list file (one IP/CIDR each line) (Required)
    -l6 string
        Domestic IPv6 list file (one IP/CIDR each line)
    -m int
        Minimum possible RTT (ms) for foreign nameservers. Packets with shorter RTT will be dropped. (default 30)
    -s int
        Minimum safe RTT (ms) for foreign nameservers. Packets with longer RTT will be accepted. (default 100)
    -t  Trustworthy mode. Foreign answers will not be checked for validity.
    -v  Verbose mode. Connection will remain open after replied until timeout.
    -w int
        Only for trustworthy foreign servers. Time (ms) during which domestic answers are prioritized. (default 50)
        
Usage examples
----

* Scenario 1: Home broadband

      shdns -b 127.0.0.1:5353 -l4 cnipv4.txt -l6 cnipv6.txt -m 30 -M 400 -s 100 -i 50
    This scenario has no trustworthy servers and users are HIGHLY RECOMMENDED to tweak the parameters by analyzing the verbose output. 
    
    **Do not use the parameters as is!**

    Hint: For those users who want to replicate ChinaDNS's behavior (no minimum RTT and safe RTT checks, always wait until the end of the delay), set `-m` to `0`, `-s` and `-i` equal to or larger than `-M`. (`-M` is similar to `-y` in ChinaDNS, default is 300)

    Sample output:
        
      $ shdns -b 127.0.0.1:5300 -l4 cnipv4.txt -l6 cnipv6.txt -m 30 -M 400 -s 100 -i 50 -v
      2019/08/26 23:02:30.320622 Loaded 8394 domestic IPv4 entries
      2019/08/26 23:02:30.323830 Loaded 1753 domestic IPv6 entries
      2019/08/26 23:02:30.324422 Using nameserver 114.114.114.114:53
      2019/08/26 23:02:30.324954 Using nameserver 223.5.5.5:53
      2019/08/26 23:02:30.325751 Using nameserver 8.8.8.8:53
      2019/08/26 23:02:30.326540 Using nameserver 1.1.1.1:53
      2019/08/26 23:02:30.327370 Listening on UDP 127.0.0.1:5300
      2019/08/26 23:02:31.876553 30793 127.0.0.1:62214 Query[A] zh.wikipedia.org. len 57
      2019/08/26 23:02:31.881897 30793 114.114.114.114:53 Answer[CNAME] zh.wikipedia.org. dyna.wikimedia.org. len 90 3ms [DROP]
      2019/08/26 23:02:31.882249 30793 114.114.114.114:53 Answer[A] dyna.wikimedia.org. 198.35.26.96 len 90 3ms GEOERR [DROP]
      2019/08/26 23:02:31.882343 30793 8.8.8.8:53 Answer[A] zh.wikipedia.org. 31.13.66.6 len 61 3ms TOOFAST [DROP]
      2019/08/26 23:02:31.887136 30793 223.5.5.5:53 Answer[CNAME] zh.wikipedia.org. dyna.wikimedia.org. len 79 8ms [DROP]
      2019/08/26 23:02:31.887276 30793 223.5.5.5:53 Answer[A] dyna.wikimedia.org. 198.35.26.96 len 79 8ms GEOERR [DROP]
      2019/08/26 23:02:31.893583 30793 8.8.8.8:53 Answer[A] zh.wikipedia.org. 66.220.151.20 len 50 14ms TOOFAST [DROP]
      2019/08/26 23:02:31.893850 30793 8.8.8.8:53 Answer[A] zh.wikipedia.org. 67.228.74.123 len 50 15ms TOOFAST [DROP]
      2019/08/26 23:02:31.895050 30793 1.1.1.1:53 Answer[A] zh.wikipedia.org. 93.46.8.89 len 50 15ms TOOFAST [DROP]
      2019/08/26 23:02:31.897547 30793 114.114.114.114:53 Answer[CNAME] zh.wikipedia.org. dyna.wikimedia.org. len 102 19ms [DROP]
      2019/08/26 23:02:31.899416 30793 114.114.114.114:53 Answer[A] dyna.wikimedia.org. 198.35.26.96 len 102 19ms GEOERR [DROP]
      2019/08/26 23:02:31.930160 30793 1.1.1.1:53 Answer[CNAME] zh.wikipedia.org. dyna.wikimedia.org. len 90 50ms [ACCEPT]
      2019/08/26 23:02:31.930418 30793 1.1.1.1:53 Answer[A] dyna.wikimedia.org. 103.102.166.224 len 90 50ms [ACCEPT]

      $ dig @127.0.0.1 -p 5300 zh.wikipedia.org

      ; <<>> DiG 9.11.3-1ubuntu1.8-Ubuntu <<>> @127.0.0.1 -p 5300 zh.wikipedia.org
      ; (1 server found)
      ;; global options: +cmd
      ;; Got answer:
      ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 30793
      ;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

      ;; OPT PSEUDOSECTION:
      ; EDNS: version: 0, flags:; udp: 1452
      ;; QUESTION SECTION:
      ;zh.wikipedia.org.              IN      A

      ;; ANSWER SECTION:
      zh.wikipedia.org.       3971    IN      CNAME   dyna.wikimedia.org.
      dyna.wikimedia.org.     285     IN      A       103.102.166.224

      ;; Query time: 54 msec
      ;; SERVER: 127.0.0.1#5300(127.0.0.1)
      ;; WHEN: Mon Aug 26 23:02:31 CST 2019
      ;; MSG SIZE  rcvd: 90
    
* Scenario 2: Home broadband + Trustworthy DNS over UDP or VPN

      shdns -b 127.0.0.1:5353 -l4 cnipv4.txt -l6 cnipv6.txt -M 400 -w 50 -t -f 208.67.222.222:443
    This scenario has non-local trustworthy foreign servers so that RTT checks are disabled. Instead, a duration (50ms) is set so that answers returned by foreign servers within 50ms (not very likely) are delayed until 50ms. This policy addresses domestic CDN issue.
    
* Scenario 3: Home broadband + Trustworthy local caching DNS proxy (e.g. DOH)

      shdns -b 127.0.0.1:5353 -l4 cnipv4.txt -l6 cnipv6.txt -M 2000 -w 50 -t -f 127.0.0.1:5300
    This is very similar to scenario 2. The only difference is that here a local caching server is set as the foreign server. A large value is used for timeout due to the time-consuming TLS handshake and `-w` is critical to be domestic CDN-friendly.

Compilation
----

  The only external package used is dnsmessage. You may need to run `go get -u golang.org/x/net/dns/dnsmessage` to get its source first. Build is straightforward.

[ChinaDNS]: https://github.com/shadowsocks/ChinaDNS
[overture]: https://github.com/shawn1m/overture
[freedns-go]: https://github.com/tuna/freedns-go
[yadd]: https://github.com/sticnarf/yadd
[ChinaDNS 2]: https://github.com/aa65535/ChinaDNS
