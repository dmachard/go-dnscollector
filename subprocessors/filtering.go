package subprocessors

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
	"gopkg.in/fsnotify.v1"
)

type FilteringProcessor struct {
	config           *dnsutils.Config
	logger           *logger.Logger
	dropDomains      bool
	mapRcodes        map[string]bool
	mapQueryIp       map[string]bool
	listFqdns        map[string]bool
	listDomainsRegex map[string]*regexp.Regexp
	fileWatcher      *fsnotify.Watcher
}

func NewFilteringProcessor(config *dnsutils.Config, logger *logger.Logger) FilteringProcessor {
	// creates a new file watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		fmt.Println("ERROR", err)
	}
	defer watcher.Close()

	d := FilteringProcessor{
		config:           config,
		logger:           logger,
		mapRcodes:        make(map[string]bool),
		mapQueryIp:       make(map[string]bool),
		listFqdns:        make(map[string]bool),
		listDomainsRegex: make(map[string]*regexp.Regexp),
		fileWatcher:      watcher,
	}

	d.LoadRcodes()
	d.LoadDomainsList()
	d.LoadQueryIpList()

	//go d.Run()
	return d
}

func (p *FilteringProcessor) LoadRcodes() {
	for _, v := range p.config.Subprocessors.Filtering.DropRcodes {
		p.mapRcodes[v] = true
	}
}

func (p *FilteringProcessor) LoadQueryIpList() {
	if len(p.config.Subprocessors.Filtering.DropQueryIpFile) > 0 {
		file, err := os.Open(p.config.Subprocessors.Filtering.DropQueryIpFile)
		if err != nil {
			p.LogError("unable to open query ip file: ", err)
		} else {

			// register the file to watch
			/*if err := p.fileWatcher.Add(p.config.Subprocessors.Filtering.DropQueryIpFile); err != nil {
				p.LogError("unable to watch ip file: ", err)
			}*/

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				queryip := strings.ToLower(scanner.Text())
				p.mapQueryIp[queryip] = true
			}
			p.LogInfo("loaded with %d query ip to the drop list", len(p.mapQueryIp))
		}

	}
}

func (p *FilteringProcessor) LoadDomainsList() {

	if len(p.config.Subprocessors.Filtering.DropFqdnFile) > 0 {
		file, err := os.Open(p.config.Subprocessors.Filtering.DropFqdnFile)
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

	if len(p.config.Subprocessors.Filtering.DropDomainFile) > 0 {
		file, err := os.Open(p.config.Subprocessors.Filtering.DropDomainFile)
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

func (p *FilteringProcessor) CheckIfDrop(dm *dnsutils.DnsMessage) bool {
	// ignore queries ?
	if !p.config.Subprocessors.Filtering.LogQueries && dm.DNS.Type == dnsutils.DnsQuery {
		return true
	}

	// ignore replies ?
	if !p.config.Subprocessors.Filtering.LogReplies && dm.DNS.Type == dnsutils.DnsReply {
		return true
	}

	// drop according to the rcode ?
	if _, ok := p.mapRcodes[dm.DNS.Rcode]; ok {
		return true
	}

	// drop according to the query ip ?
	if _, ok := p.mapQueryIp[dm.NetworkInfo.QueryIp]; ok {
		return true
	}

	// drop domains ?
	if p.dropDomains {
		// fqdn
		if _, ok := p.listFqdns[dm.DNS.Qname]; ok {
			return true
		}

		// partiel fqdn with regexp
		for _, p := range p.listDomainsRegex {
			if p.MatchString(dm.DNS.Qname) {
				return true
			}
		}
	}

	return false
}
