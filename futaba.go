package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"syscall"
	"time"

	"github.com/go-redis/redis"
	"github.com/miekg/dns"
)

func printVersion() {
	const version = "0.0.2"
	fmt.Println("futaba version", version)
}

func setMaxFiles() {

	var (
		r syscall.Rlimit
	)

	platform := runtime.GOOS

	r.Cur = 256
	r.Max = 256

	if platform == "linux" {
		r.Cur = 65536
		r.Max = 65536
	}

	err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &r)
	if err != nil {
		log.Printf("set max files failed, error: %s\n", err.Error())
	}
}

type Server struct {
	accessLogger *log.Logger
	errorLogger  *log.Logger
	rdb          *redis.Client
	expiration   time.Duration
	servers      []string
}

type Answer struct {
	CNAME []string
	IP    []net.IP
}

func (answer *Answer) IPs(answers map[string]*Answer) string {
	str := ""
	for _, ip := range answer.IP {
		str += ip.String() + ","
	}
	for _, cname := range answer.CNAME {
		ips := answers[cname].IPs(answers)
		if ips != "-" {
			str += ips + ","
		}
	}
	if str == "" {
		return "-"
	} else {
		return str[:len(str)-1]
	}
}

func (answer *Answer) CNAMEs(answers map[string]*Answer) string {
	str := ""
	for _, cname := range answer.CNAME {
		str += cname + ","
		cnames := answers[cname].CNAMEs(answers)
		if cnames != "-" {
			str += cnames + ","
		}
	}
	if str == "" {
		return "-"
	} else {
		return str[:len(str)-1]
	}
}

type Domain string

func (domain Domain) AllChild(cnames map[Domain]*Domains) []Domain {
	var result []Domain
	if domains, found := cnames[domain]; found {
		for _, domain := range *domains {
			result = append(result, domain)
			result = append(result, domain.AllChild(cnames)...)
		}
	}
	return result
}

type Domains []Domain

func (domains *Domains) Strings() []string {
	str := make([]string, 0, len(*domains))
	for _, domain := range *domains {
		str = append(str, string(domain))
	}
	return str
}

type Session struct {
	kv      map[string]*Domains
	cnames  map[Domain]*Domains
	req     *dns.Msg
	resp    *dns.Msg
	answers map[string]*Answer
	epoch   time.Time
	server  string
	dns.ResponseWriter
}

func (session *Session) parseAnswer() {
	session.answers = make(map[string]*Answer)
	for _, question := range session.req.Question {
		session.answers[question.Name] = new(Answer)
	}
	session.kv = make(map[string]*Domains)
	session.cnames = make(map[Domain]*Domains)
	for _, answer := range session.resp.Answer {
		switch answer.(type) {
		case *dns.A:
			rr := answer.(*dns.A)
			if ans, found := session.answers[answer.Header().Name]; found {
				ans.IP = append(ans.IP, rr.A)
			}
			domains, found := session.kv[rr.A.String()]
			if !found {
				domains = new(Domains)
				session.kv[rr.A.String()] = domains
			}
			*domains = append(*domains, Domain(answer.Header().Name))
			*domains = append(*domains, Domain(answer.Header().Name).AllChild(session.cnames)...)
		case *dns.AAAA:
			rr := answer.(*dns.AAAA)
			if ans, found := session.answers[answer.Header().Name]; found {
				ans.IP = append(ans.IP, rr.AAAA)
			}
			domains, found := session.kv[rr.AAAA.String()]
			if !found {
				domains = new(Domains)
				session.kv[rr.AAAA.String()] = domains
			}
			*domains = append(*domains, Domain(answer.Header().Name))
			*domains = append(*domains, Domain(answer.Header().Name).AllChild(session.cnames)...)
		case *dns.CNAME:
			rr := answer.(*dns.CNAME)
			if ans, found := session.answers[answer.Header().Name]; found {
				ans.CNAME = append(ans.CNAME, rr.Target)
			}
			if _, found := session.answers[rr.Target]; !found {
				session.answers[rr.Target] = new(Answer)
			}
			domains, found := session.cnames[Domain(rr.Target)]
			if !found {
				domains = new(Domains)
				session.cnames[Domain(rr.Target)] = domains
			}
			*domains = append(*domains, Domain(answer.Header().Name))
			*domains = append(*domains, Domain(answer.Header().Name).AllChild(session.cnames)...)
		}
	}
}

func (s *Server) setExpire(session *Session) {
	for k, _ := range session.kv {
		if _, err := s.rdb.Expire(k, s.expiration).Result(); err != nil {
			s.errorLogger.Printf("redis set [%s] expiration %v failed: %s\n", k, s.expiration, err.Error())
		}
	}
}

func (s *Server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {

	var (
		resp *dns.Msg
		err  error
	)

	session := &Session{
		req:            req,
		ResponseWriter: w,
		epoch:          time.Now(),
		server:         "-",
	}

	defer s.Log(session)

	for i := 0; i < len(s.servers); i++ {
		if resp, err = dns.Exchange(req, fmt.Sprintf("%s:53", s.servers[i])); err != nil {
			s.errorLogger.Printf("dns exchange failed, error: %s\n", err.Error())
		} else {
			session.server = s.servers[i]
			break
		}
	}

	if resp != nil {
		session.resp = resp
		session.parseAnswer()
		for k, v := range session.kv {
			if _, err := s.rdb.SAdd(k, v.Strings()).Result(); err != nil {
				s.errorLogger.Printf("redis write failed, error: %s\n", err.Error())
			}
		}
		if err := w.WriteMsg(resp); err != nil {
			s.errorLogger.Printf("write failed, error: %s\n", err.Error())
		}
		go s.setExpire(session)
	}
}

func (s *Server) Log(session *Session) {
	for _, question := range session.req.Question {
		if answer, found := session.answers[question.Name]; found {
			s.accessLogger.Printf("%s\t%s\t%s\t%d\t%d\t%s\t%s\t%s\n", session.RemoteAddr().String(), session.LocalAddr().String(), question.Name, 
				session.epoch.UnixNano()/1000000, time.Now().UnixNano()/1000000, answer.IPs(session.answers), answer.CNAMEs(session.answers), session.server)
		} else {
			s.accessLogger.Printf("%s\t%s\t%s\t%d\t%d\t-\t-\t%s\n", session.RemoteAddr().String(), session.LocalAddr().String(), question.Name, 
				session.epoch.UnixNano()/1000000, time.Now().UnixNano()/1000000, session.server)
		}
	}
}

func (s *Server) SetLogPath() error {

	if logFile, err := os.OpenFile("./futaba.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644); err != nil {
		log.Printf("create futaba.log failed, error: %s\n", err.Error())
		return err
	} else {
		s.errorLogger = new(log.Logger)
		s.errorLogger.SetFlags(log.LstdFlags)
		s.errorLogger.SetOutput(logFile)
	}

	if logFile, err := os.OpenFile("./access.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644); err != nil {
		log.Printf("create access.log failed, error: %s\n", err.Error())
		return err
	} else {
		s.accessLogger = new(log.Logger)
		s.accessLogger.SetOutput(logFile)
		return nil
	}
}

func main() {

	var (
		printVer   bool
		redisHost  string
		redisPort  int
		redisAuth  string
		localHost  string
		localPort  int
		dnsHost    string
		resolvconf string
		expiration string
		err        error
	)

	flag.BoolVar(&printVer, "v", false, "print version")
	flag.StringVar(&redisHost, "h", "127.0.0.1", "redis host")
	flag.IntVar(&redisPort, "p", 6379, "redis port")
	flag.StringVar(&redisAuth, "a", "", "redis auth password")
	flag.StringVar(&localHost, "local_host", "0.0.0.0", "dns server listen host")
	flag.IntVar(&localPort, "local_port", 53, "dns server listen port")
	flag.StringVar(&dnsHost, "d", "", "dns resolver addr")
	flag.StringVar(&resolvconf, "c", "/etc/resolv.conf", "local resolv.conf location")
	flag.StringVar(&expiration, "e", "24h", "set redis key expiration")

	flag.Parse()

	if printVer {
		printVersion()
		os.Exit(0)
	}

	/* set maximum number of cpus */
	runtime.GOMAXPROCS(0)

	server := new(Server)
	if err = server.SetLogPath(); err != nil {
		os.Exit(1)
	}

	if dnsHost != "" {
		server.servers = append(server.servers, dnsHost)
	}
	if clientConfig, err := dns.ClientConfigFromFile(resolvconf); err != nil {
		log.Printf("resolv.conf parse failed: %s\n", err.Error())
	} else {
		server.servers = append(server.servers, clientConfig.Servers...)
	}
	if len(server.servers) == 0 {
		log.Printf("with no dns resolver addr")
		os.Exit(1)
	}

	if server.expiration, err = time.ParseDuration(expiration); err != nil {
		log.Printf("expiration %s parse failed: %s\n", expiration, err.Error())
		os.Exit(1)
	}

	setMaxFiles()

	server.rdb = redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", redisHost, redisPort),
		Password: redisAuth,
	})

	log.Fatal(dns.ListenAndServe(fmt.Sprintf("%s:%d", localHost, localPort), "udp", server))
}