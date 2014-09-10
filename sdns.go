package main

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"flag"
)

var queryLog = true

var (
	soaNS          = "dns01.dns.routemeister.net."
	soaMbox        = "simon.routemeister.net."
	soaSerial      = uint32(1)
	maxHostnameLen = 100
)

// SQL defaults.
var (
	sqlHostname = "localhost"
	sqlPort = 3306
	sqlUsername = "sdns"
	sqlPassword = ""
	sqlDBName = "sdns"
)

type globalConfig struct {
	httpApiKey string
}

var config = &globalConfig{
}

var (
	defaultNSNames = []string{"dns01.dns.routemeister.net.", "dns02.dns.routemeister.net."}
	defaultNSCount = 2
	defaultNSExtra = []dns.RR{
		dns.RR(&dns.A{A: net.IPv4(213, 180, 92, 175), Hdr: dns.RR_Header{Name: "dns01.dns.routemeister.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600}}),
		dns.RR(&dns.A{A: net.IPv4(213, 180, 92, 176), Hdr: dns.RR_Header{Name: "dns02.dns.routemeister.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600}}),
	}
)

type StatsCounter struct {
	start          time.Time
	updatesValid   uint64
	updatesInvalid uint64
	queriesInvalid uint64
	queriesNS      uint64
	queriesSOA     uint64
	queriesA       uint64
	queriesAAAA    uint64
	queriesOther   uint64
	queriesMatch   uint64
	queriesMiss    uint64
}

func (sc *StatsCounter) Snapshot() *StatsCounter {
	ret := *sc
	ret.start = time.Now()
	return &ret
}

func (sc *StatsCounter) Print() {
	fmt.Println("Updates valid:", sc.updatesValid)
	fmt.Println("Updates invalid:", sc.updatesInvalid)
	fmt.Println("Queries invalid:", sc.queriesInvalid)
	fmt.Println("Queries match", sc.queriesMatch)
	fmt.Println("Queries miss", sc.queriesMiss)
	fmt.Println("Queries NS", sc.queriesNS)
	fmt.Println("Queries SOA", sc.queriesSOA)
	fmt.Println("Queries A", sc.queriesA)
	fmt.Println("Queries AAAA", sc.queriesAAAA)
	fmt.Println("Queries Other", sc.queriesOther)
}

func (sc *StatsCounter) PrintPerSecond(prev *StatsCounter) {
	tDiff := uint64(time.Now().Unix() - prev.start.Unix())
	fmt.Println("Updates valid (/s):", (sc.updatesValid-prev.updatesValid)/tDiff)
	fmt.Println("Updates invalid (/s):", (sc.updatesInvalid-prev.updatesInvalid)/tDiff)
	fmt.Println("Queries invalid (/s):", (sc.queriesInvalid-prev.queriesInvalid)/tDiff)
	fmt.Println("Queries match (/s)", (sc.queriesMatch-prev.queriesMatch)/tDiff)
	fmt.Println("Queries miss (/s)", (sc.queriesMiss-prev.queriesMiss)/tDiff)
	fmt.Println("Queries NS (/s)", (sc.queriesNS-prev.queriesNS)/tDiff)
	fmt.Println("Queries SOA (/s)", (sc.queriesSOA-prev.queriesSOA)/tDiff)
	fmt.Println("Queries A (/s)", (sc.queriesA-prev.queriesA)/tDiff)
	fmt.Println("Queries AAAA (/s)", (sc.queriesAAAA-prev.queriesAAAA)/tDiff)
	fmt.Println("Queries Other (/s)", (sc.queriesOther-prev.queriesOther)/tDiff)
}

func NewStatsCounter() *StatsCounter {
	ret := &StatsCounter{start: time.Now()}
	return ret
}

type DomainHandler struct {
	ARecords    map[string][]net.IP
	AAAARecords map[string][]net.IP
	stats       *StatsCounter
	lock        sync.RWMutex
}

func (dh *DomainHandler) clearHost(name string) error {
	dh.lock.Lock()
	delete(dh.ARecords, name)
	delete(dh.AAAARecords, name)
	dh.lock.Unlock()
	return nil
}

func (dh *DomainHandler) setHost(name, dstIPStr string) error {
	if len(name) > maxHostnameLen || len(name) < 2 {
		return errors.New("invalid hostname")
	}
	if strings.HasSuffix(name, ".") != true {
		name = name + "."
	}
	dstIP := net.ParseIP(dstIPStr)
	if dstIP == nil {
		dh.stats.updatesInvalid += 1
		return errors.New("invalid destination address")
	}
	ip4 := dstIP.To4()
	if ip4 == nil {
		ip6 := dstIP.To16()
		if ip6 == nil {
			dh.stats.updatesInvalid += 1
			return errors.New("invalid destination address")
		} else {
			name = strings.ToLower(name)
			dh.lock.Lock()
			dh.AAAARecords[name] = []net.IP{ip6}
			delete(dh.ARecords, name)
			dh.lock.Unlock()
			dh.stats.updatesValid += 1
		}
	} else {
		name = strings.ToLower(name)
		dh.lock.Lock()
		dh.ARecords[name] = []net.IP{ip4}
		delete(dh.AAAARecords, name)
		dh.lock.Unlock()
		dh.stats.updatesValid += 1
	}
	return nil
}

func (dh *DomainHandler) setA(name, dstIPStr string) error {
	if len(name) > maxHostnameLen || len(name) < 2 {
		dh.stats.updatesInvalid += 1
		return errors.New("invalid hostname")
	}
	if strings.HasSuffix(name, ".") != true {
		name = name + "."
	}
	dstIP := net.ParseIP(dstIPStr)
	if dstIP == nil {
		dh.stats.updatesInvalid += 1
		return errors.New("invalid destination address")
	}
	ip4 := dstIP.To4()
	if ip4 == nil {
		dh.stats.updatesInvalid += 1
		return errors.New("invalid destination address")
	}
	dh.lock.Lock()
	dh.ARecords[strings.ToLower(name)] = []net.IP{ip4}
	dh.stats.updatesValid += 1
	dh.lock.Unlock()
	return nil
}

func (dh *DomainHandler) setAAAA(name, dstIPStr string) error {
	if len(name) > maxHostnameLen || len(name) < 2 {
		dh.stats.updatesInvalid += 1
		return errors.New("invalid hostname")
	}
	if strings.HasSuffix(name, ".") != true {
		name = name + "."
	}
	dstIP := net.ParseIP(dstIPStr)
	if dstIP == nil {
		dh.stats.updatesInvalid += 1
		return errors.New("invalid destination address")
	}
	ip6 := dstIP.To16()
	if ip6 == nil {
		dh.stats.updatesInvalid += 1
		return errors.New("invalid destination address")
	}
	dh.lock.Lock()
	dh.AAAARecords[strings.ToLower(name)] = []net.IP{ip6}
	dh.stats.updatesValid += 1
	dh.lock.Unlock()
	return nil
}

func NewDomainHandler() *DomainHandler {
	dh := &DomainHandler{ARecords: make(map[string][]net.IP), AAAARecords: make(map[string][]net.IP), stats: NewStatsCounter()}
	return dh
}

var DefaultDomainHandler = NewDomainHandler()

func getDefaultNS(domainName string) []dns.RR {
	ret := make([]dns.RR, defaultNSCount, defaultNSCount)
	for pos, nsName := range defaultNSNames {
		ns_hdr := dns.RR_Header{Name: domainName, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600}
		ns_rr := dns.RR(&dns.NS{Ns: nsName, Hdr: ns_hdr})
		ret[pos] = ns_rr
	}
	return ret
}

func getDefaultSoa(domainName string) []dns.RR {
	ret := make([]dns.RR, 1, 1)
	soa_hdr := dns.RR_Header{Name: domainName, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600}
	soa_rr := dns.RR(&dns.SOA{Hdr: soa_hdr, Ns: soaNS, Mbox: soaMbox, Serial: soaSerial, Refresh: 7200, Retry: 1800, Expire: 1209600, Minttl: 300})
	ret[0] = soa_rr
	return ret
}

func handleRequests(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Compress = false
	msg.Authoritative = true
	remoteAddr := w.RemoteAddr()
	if queryLog {
		fmt.Printf("Query: ip=%v questions=%v\n", remoteAddr, len(msg.Question))
	}

	for _, question := range r.Question {
		if queryLog {
			fmt.Printf("Query: ip=%v name=%v type=%v\n", remoteAddr, question.Name, question.Qtype)
		}
		if len(question.Name) < 2 {
			msg.SetRcode(r, dns.RcodeServerFailure)
			DefaultDomainHandler.stats.queriesInvalid += 1
			break
		}
		name := strings.ToLower(question.Name)
		switch question.Qtype {
		case dns.TypeNS:
			DefaultDomainHandler.stats.queriesNS += 1
			msg.Answer = getDefaultNS(question.Name)
			msg.Extra = defaultNSExtra
		case dns.TypeSOA:
			DefaultDomainHandler.stats.queriesSOA += 1
			msg.Answer = getDefaultSoa(question.Name)
			msg.Ns = getDefaultNS(question.Name)
			msg.Extra = defaultNSExtra
		case dns.TypeA:
			DefaultDomainHandler.stats.queriesA += 1
			DefaultDomainHandler.lock.RLock()
			if records, ok := DefaultDomainHandler.ARecords[name]; ok {
				DefaultDomainHandler.stats.queriesMatch += 1
				for _, ip := range records {
					a_hdr := dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}
					msg.Answer = append(msg.Answer, dns.RR(&dns.A{Hdr: a_hdr, A: ip}))
				}
			} else {
				DefaultDomainHandler.stats.queriesMiss += 1
			}
			DefaultDomainHandler.lock.RUnlock()
		case dns.TypeAAAA:
			DefaultDomainHandler.stats.queriesAAAA += 1
			DefaultDomainHandler.lock.RLock()
			if records, ok := DefaultDomainHandler.AAAARecords[name]; ok {
				DefaultDomainHandler.stats.queriesMatch += 1
				for _, ip := range records {
					a_hdr := dns.RR_Header{Name: question.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300}
					msg.Answer = append(msg.Answer, dns.RR(&dns.AAAA{Hdr: a_hdr, AAAA: ip}))
				}
			} else {
				DefaultDomainHandler.stats.queriesMiss += 1
			}
			DefaultDomainHandler.lock.RUnlock()
		default:
			DefaultDomainHandler.stats.queriesOther += 1
		}
	}

	w.WriteMsg(msg)
}

func startDNSListener(mux *dns.ServeMux, net string, port int) {
	fmt.Printf("Starting DNS listener on %s:%d\n", net, port)
	server := &dns.Server{Handler: mux, Addr: ":" + strconv.Itoa(port), Net: net, TsigSecret: nil}
	err := server.ListenAndServe()
	if err != nil {
		fmt.Printf("Failed to setup the "+net+" server: %s\n", err.Error())
	}
}

func printStats(dh *DomainHandler) {
	var snapshot *StatsCounter
	for {
		snapshot = dh.stats.Snapshot()
		time.Sleep(30 * time.Second)
		fmt.Println("-- Stats")
		dh.lock.RLock()
		fmt.Println("A records:", len(dh.ARecords))
		fmt.Println("AAAA records:", len(dh.AAAARecords))
		dh.lock.RUnlock()
		fmt.Println()
		dh.stats.Print()
		if snapshot != nil {
			fmt.Println()
			dh.stats.PrintPerSecond(snapshot)
		}
		fmt.Println("--------")
	}
}

func main() {
	var (
		dnsPort = flag.Int("dnsport", 8053, "port to use for dns queries")
		httpPort = flag.Int("httpport", 8081, "port to use for http api queries")
		cSqlHostname = flag.String("sqlhost", sqlHostname, "sql server hostname")
		cSqlUsername = flag.String("sqluser", sqlUsername, "sql server username")
		cSqlPassword = flag.String("sqlpass", sqlPassword, "sql server password")
		cSqlDBName = flag.String("sqldb", sqlDBName, "sql server database name")
	)
	flag.StringVar(&config.httpApiKey, "httpapikey", "", "key used for communication over http api")
	flag.Parse()
    if config.httpApiKey == "" {
        fmt.Println("ERROR: Missing required flag httpapikey")
        flag.PrintDefaults()
        os.Exit(1)
    }

	mux := dns.NewServeMux()
	mux.HandleFunc(".", handleRequests)
	cnt, err := loadRecords(DefaultDomainHandler, *cSqlHostname, *cSqlUsername, *cSqlPassword, *cSqlDBName)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Loaded records", cnt)
	go startDNSListener(mux, "tcp", *dnsPort)
	go startDNSListener(mux, "udp", *dnsPort)
	go startHTTPListener(*httpPort)
	go printStats(DefaultDomainHandler)
	fmt.Println("Runnning")
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
forever:
	for {
		select {
		case s := <-sig:
			fmt.Printf("Signal (%d) received, stopping\n", s)
			break forever
		}
	}
}
