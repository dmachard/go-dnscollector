package transformers

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
	"gopkg.in/fsnotify.v1"
	"inet.af/netaddr"
)

type FilteringProcessor struct {
	config               *dnsutils.Config
	logger               *logger.Logger
	dropDomains          bool
	keepDomains          bool
	mapRcodes            map[string]bool
	ipsetDrop            *netaddr.IPSet
	ipsetKeep            *netaddr.IPSet
	listFqdns            map[string]bool
	listDomainsRegex     map[string]*regexp.Regexp
	listKeepFqdns        map[string]bool
	listKeepDomainsRegex map[string]*regexp.Regexp
	fileWatcher          *fsnotify.Watcher
	name                 string
	downsample           int
	downsampleCount      int
	activeFilters        []func(dm *dnsutils.DnsMessage) bool
}

func NewFilteringProcessor(config *dnsutils.Config, logger *logger.Logger, name string) FilteringProcessor {
	// creates a new file watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		fmt.Println("ERROR", err)
	}
	defer watcher.Close()

	d := FilteringProcessor{
		config:               config,
		logger:               logger,
		mapRcodes:            make(map[string]bool),
		ipsetDrop:            &netaddr.IPSet{},
		ipsetKeep:            &netaddr.IPSet{},
		listFqdns:            make(map[string]bool),
		listDomainsRegex:     make(map[string]*regexp.Regexp),
		listKeepFqdns:        make(map[string]bool),
		listKeepDomainsRegex: make(map[string]*regexp.Regexp),
		fileWatcher:          watcher,
		name:                 name,
	}

	d.LoadRcodes()
	d.LoadDomainsList()
	d.LoadQueryIpList()

	d.LoadActiveFilters()

	//go d.Run()
	return d
}

func (p *FilteringProcessor) LoadActiveFilters() {
	// TODO: Change to iteration through Filtering to add filters in custom order.

	if !p.config.Transformers.Filtering.LogQueries {
		p.activeFilters = append(p.activeFilters, p.ignoreQueryFilter)
	}

	if !p.config.Transformers.Filtering.LogReplies {
		p.activeFilters = append(p.activeFilters, p.ignoreReplyFilter)
	}

	if len(p.mapRcodes) > 0 {
		p.activeFilters = append(p.activeFilters, p.rCodeFilter)
	}

	if len(p.config.Transformers.Filtering.KeepQueryIpFile) > 0 || len(p.config.Transformers.Filtering.DropQueryIpFile) > 0 {
		p.activeFilters = append(p.activeFilters, p.ipFilter)
	}

	if len(p.listFqdns) > 0 {
		p.activeFilters = append(p.activeFilters, p.dropFqdnFilter)
	}

	if len(p.listDomainsRegex) > 0 {
		p.activeFilters = append(p.activeFilters, p.dropDomainRegexFilter)
	}

	if len(p.listKeepFqdns) > 0 {
		p.activeFilters = append(p.activeFilters, p.keepFqdnFilter)
	}

	if len(p.listKeepDomainsRegex) > 0 {
		p.activeFilters = append(p.activeFilters, p.keepDomainRegexFilter)
	}

	// set downsample if desired
	if p.config.Transformers.Filtering.Downsample > 0 {
		p.downsample = p.config.Transformers.Filtering.Downsample
		p.downsampleCount = 0
		p.activeFilters = append(p.activeFilters, p.downsampleFilter)
	}
}

func (p *FilteringProcessor) LoadRcodes() {
	for _, v := range p.config.Transformers.Filtering.DropRcodes {
		p.mapRcodes[v] = true
	}
}

func (p *FilteringProcessor) loadQueryIpList(fname string, drop bool) (uint64, error) {
	file, err := os.Open(fname)
	if err != nil {
		return 0, err
	}

	// register the file to watch
	/*if err := p.fileWatcher.Add(fname); err != nil {
		p.LogError("unable to watch ip file: ", err)
	}*/

	scanner := bufio.NewScanner(file)
	var read uint64
	var ipsetbuilder netaddr.IPSetBuilder
	for scanner.Scan() {
		read++
		ipOrPrefix := strings.ToLower(scanner.Text())
		prefix, err := netaddr.ParseIPPrefix(ipOrPrefix)
		if err != nil {
			ip, err := netaddr.ParseIP(ipOrPrefix)
			if err != nil {
				p.LogError("%s in in %s is neither an IP address nor a prefix", ipOrPrefix, fname)
				continue
			}
			ipsetbuilder.Add(ip)
			continue
		}
		ipsetbuilder.AddPrefix(prefix)
	}
	if drop {
		p.ipsetDrop, err = ipsetbuilder.IPSet()
	} else {
		p.ipsetKeep, err = ipsetbuilder.IPSet()
	}

	return read, err
}

func (p *FilteringProcessor) LoadQueryIpList() {
	if len(p.config.Transformers.Filtering.DropQueryIpFile) > 0 {
		read, err := p.loadQueryIpList(p.config.Transformers.Filtering.DropQueryIpFile, true)
		if err != nil {
			p.LogError("unable to open query ip file: ", err)
		}
		p.LogInfo("loaded with %d query ip to the drop list", read)
	}

	if len(p.config.Transformers.Filtering.KeepQueryIpFile) > 0 {
		read, err := p.loadQueryIpList(p.config.Transformers.Filtering.KeepQueryIpFile, false)
		if err != nil {
			p.LogError("unable to open query ip file: ", err)
		}
		p.LogInfo("loaded with %d query ip to the keep list", read)
	}
}

func (p *FilteringProcessor) LoadDomainsList() {
	if len(p.config.Transformers.Filtering.DropFqdnFile) > 0 {
		file, err := os.Open(p.config.Transformers.Filtering.DropFqdnFile)
		if err != nil {
			p.LogError("unable to open fqdn file: ", err)
			p.dropDomains = true
		} else {

			// register the file to watch
			/*if err := p.fileWatcher.Add(p.config.Subprocessors.Filtering.DropFqdnFile); err != nil {
				p.LogError("unable to watch fqdn file: ", err)
			}*/

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				fqdn := strings.ToLower(scanner.Text())
				p.listFqdns[fqdn] = true
			}
			p.LogInfo("loaded with %d fqdn to the drop list", len(p.listFqdns))
			p.dropDomains = true
		}

	}

	if len(p.config.Transformers.Filtering.DropDomainFile) > 0 {
		file, err := os.Open(p.config.Transformers.Filtering.DropDomainFile)
		if err != nil {
			p.LogError("unable to open regex list file: ", err)
			p.dropDomains = true
		} else {
			// register the file to watch
			/*if err := p.fileWatcher.Add(p.config.Subprocessors.Filtering.DropDomainFile); err != nil {
				p.LogError("unable to watch domain file: ", err)
			}*/

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				domain := strings.ToLower(scanner.Text())
				p.listDomainsRegex[domain] = regexp.MustCompile(domain)
			}
			p.LogInfo("loaded with %d domains to the drop list", len(p.listDomainsRegex))
			p.dropDomains = true
		}
	}

	if len(p.config.Transformers.Filtering.KeepFqdnFile) > 0 {
		file, err := os.Open(p.config.Transformers.Filtering.KeepFqdnFile)
		if err != nil {
			p.LogError("unable to open KeepFqdnFile file: ", err)
			p.keepDomains = false
		} else {
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				keepDomain := strings.ToLower(scanner.Text())
				p.listKeepFqdns[keepDomain] = true
			}
			p.LogInfo("loaded with %d fqdns to the keep list", len(p.listKeepFqdns))
			p.keepDomains = true
		}
	}

	if len(p.config.Transformers.Filtering.KeepDomainFile) > 0 {
		file, err := os.Open(p.config.Transformers.Filtering.KeepDomainFile)
		if err != nil {
			p.LogError("unable to open KeepDomainFile file: ", err)
			p.keepDomains = false
		} else {
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				keepDomain := strings.ToLower(scanner.Text())
				p.listKeepDomainsRegex[keepDomain] = regexp.MustCompile(keepDomain)
			}
			p.LogInfo("loaded with %d domains to the keep list", len(p.listKeepDomainsRegex))
			p.keepDomains = true
		}
	}
}

func (p *FilteringProcessor) LogInfo(msg string, v ...interface{}) {
	p.logger.Info("filtering - "+msg, v...)
}

func (p *FilteringProcessor) LogError(msg string, v ...interface{}) {
	p.logger.Error("filtering - "+msg, v...)
}

func (p *FilteringProcessor) Run() {
	for {
		select {
		// watch for events
		case event := <-p.fileWatcher.Events:
			fmt.Printf("EVENT! %#v\n", event)

			// watch for errors
		case err := <-p.fileWatcher.Errors:
			fmt.Println("ERROR", err)
		}
	}
}

func (p *FilteringProcessor) ignoreQueryFilter(dm *dnsutils.DnsMessage) bool {
	// ignore queries ?
	if dm.DNS.Type == dnsutils.DnsQuery {
		return true
	}
	return false
}

func (p *FilteringProcessor) ignoreReplyFilter(dm *dnsutils.DnsMessage) bool {
	// ignore replies ?
	if dm.DNS.Type == dnsutils.DnsReply {
		return true
	}
	return false
}

func (p *FilteringProcessor) rCodeFilter(dm *dnsutils.DnsMessage) bool {
	// drop according to the rcode ?
	if _, ok := p.mapRcodes[dm.DNS.Rcode]; ok {
		return true
	}
	return false
}

func (p *FilteringProcessor) ipFilter(dm *dnsutils.DnsMessage) bool {
	ip, _ := netaddr.ParseIP(dm.NetworkInfo.QueryIp)
	if p.ipsetKeep.Contains(ip) {
		return false
	}
	if p.ipsetDrop.Contains(ip) {
		return true
	}
	return false
}

func (p *FilteringProcessor) dropFqdnFilter(dm *dnsutils.DnsMessage) bool {
	if _, ok := p.listFqdns[dm.DNS.Qname]; ok {
		return true
	}
	return false
}

func (p *FilteringProcessor) dropDomainRegexFilter(dm *dnsutils.DnsMessage) bool {
	// partial fqdn with regexp
	for _, d := range p.listDomainsRegex {
		if d.MatchString(dm.DNS.Qname) {
			return true
		}
	}
	return false
}

func (p *FilteringProcessor) keepFqdnFilter(dm *dnsutils.DnsMessage) bool {
	if _, ok := p.listKeepFqdns[dm.DNS.Qname]; ok {
		return false
	}
	return true
}

func (p *FilteringProcessor) keepDomainRegexFilter(dm *dnsutils.DnsMessage) bool {
	// partial fqdn with regexp
	for _, d := range p.listKeepDomainsRegex {
		if d.MatchString(dm.DNS.Qname) {
			return false
		}
	}
	return true
}

func (p *FilteringProcessor) downsampleFilter(dm *dnsutils.DnsMessage) bool {
	// drop all except every nth entry
	p.downsampleCount += 1
	if p.downsampleCount%p.downsample != 0 {
		return true
	} else if p.downsampleCount%p.downsample == 0 {
		p.downsampleCount = 0
		return false
	}
	return true
}

func (p *FilteringProcessor) CheckIfDrop(dm *dnsutils.DnsMessage) bool {
	if len(p.activeFilters) == 0 {
		return false
	}

	var value bool
	for _, fn := range p.activeFilters {
		value = fn(dm)
		if value == true {
			return true
		}
	}

	return false
}
