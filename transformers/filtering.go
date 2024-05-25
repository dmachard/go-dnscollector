package transformers

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
	"inet.af/netaddr"
)

type FilteringTransform struct {
	GenericTransformer
	mapRcodes                              map[string]bool
	ipsetDrop, ipsetKeep, rDataIpsetKeep   *netaddr.IPSet
	listFqdns, listKeepFqdns               map[string]bool
	listDomainsRegex, listKeepDomainsRegex map[string]*regexp.Regexp
	downsample, downsampleCount            int
}

func NewFilteringTransform(config *pkgconfig.ConfigTransformers, logger *logger.Logger, name string, instance int, nextWorkers []chan dnsutils.DNSMessage) *FilteringTransform {
	t := &FilteringTransform{GenericTransformer: NewTransformer(config, logger, "filtering", name, instance, nextWorkers)}
	t.mapRcodes = make(map[string]bool)
	t.ipsetDrop = &netaddr.IPSet{}
	t.ipsetKeep = &netaddr.IPSet{}
	t.rDataIpsetKeep = &netaddr.IPSet{}
	t.listFqdns = make(map[string]bool)
	t.listDomainsRegex = make(map[string]*regexp.Regexp)
	t.listKeepFqdns = make(map[string]bool)
	t.listKeepDomainsRegex = make(map[string]*regexp.Regexp)
	return t
}

func (t *FilteringTransform) GetTransforms() ([]Subtransform, error) {
	subtransforms := []Subtransform{}

	if err := t.LoadRcodes(); err != nil {
		return nil, err
	}
	if err := t.LoadDomainsList(); err != nil {
		return nil, err
	}
	if err := t.LoadQueryIPList(); err != nil {
		return nil, err
	}
	if err := t.LoadrDataIPList(); err != nil {
		return nil, err
	}

	if !t.config.Filtering.LogQueries {
		subtransforms = append(subtransforms, Subtransform{name: "filtering:drop-queries", processFunc: t.dropQueryFilter})
	}
	if !t.config.Filtering.LogReplies {
		subtransforms = append(subtransforms, Subtransform{name: "filtering:drop-replies", processFunc: t.dropReplyFilter})
	}
	if len(t.mapRcodes) > 0 {
		subtransforms = append(subtransforms, Subtransform{name: "filtering:drop-rcode", processFunc: t.dropRCodeFilter})
	}
	if len(t.config.Filtering.KeepQueryIPFile) > 0 {
		subtransforms = append(subtransforms, Subtransform{name: "filtering:keep-queryip", processFunc: t.keepQueryIPFilter})
	}
	if len(t.config.Filtering.DropQueryIPFile) > 0 {
		subtransforms = append(subtransforms, Subtransform{name: "filtering:drop-queryip", processFunc: t.dropQueryIPFilter})
	}
	if len(t.config.Filtering.KeepRdataFile) > 0 {
		subtransforms = append(subtransforms, Subtransform{name: "filtering:keep-rdata", processFunc: t.keepRdataFilter})
	}
	if len(t.listFqdns) > 0 {
		subtransforms = append(subtransforms, Subtransform{name: "filtering:drop-fqdn", processFunc: t.dropFqdnFilter})
	}
	if len(t.listDomainsRegex) > 0 {
		subtransforms = append(subtransforms, Subtransform{name: "filtering:drop-domain", processFunc: t.dropDomainRegexFilter})
	}
	if len(t.listKeepFqdns) > 0 {
		subtransforms = append(subtransforms, Subtransform{name: "filtering:keep-fqdn", processFunc: t.keepFqdnFilter})
	}
	if len(t.listKeepDomainsRegex) > 0 {
		subtransforms = append(subtransforms, Subtransform{name: "filtering:keep-domain", processFunc: t.keepDomainRegexFilter})
	}
	if t.config.Filtering.Downsample > 0 {
		t.downsample = t.config.Filtering.Downsample
		t.downsampleCount = 0
		subtransforms = append(subtransforms, Subtransform{name: "filtering:downsampling", processFunc: t.downsampleFilter})
	}
	return subtransforms, nil
}

func (t *FilteringTransform) LoadRcodes() error {
	// empty
	for key := range t.mapRcodes {
		delete(t.mapRcodes, key)
	}

	// add
	for _, v := range t.config.Filtering.DropRcodes {
		t.mapRcodes[v] = true
	}
	return nil
}

func (t *FilteringTransform) LoadQueryIPList() error {
	if len(t.config.Filtering.DropQueryIPFile) > 0 {
		read, err := t.loadQueryIPList(t.config.Filtering.DropQueryIPFile, true)
		if err != nil {
			return fmt.Errorf("unable to open query ip file: %w", err)
		}
		t.LogInfo("loaded with %d query ip to the drop list", read)
	}

	if len(t.config.Filtering.KeepQueryIPFile) > 0 {
		read, err := t.loadQueryIPList(t.config.Filtering.KeepQueryIPFile, false)
		if err != nil {
			return fmt.Errorf("unable to open query ip file: %w", err)
		}
		t.LogInfo("loaded with %d query ip to the keep list", read)
	}
	return nil
}

func (t *FilteringTransform) LoadrDataIPList() error {
	if len(t.config.Filtering.KeepRdataFile) > 0 {
		read, err := t.loadKeepRdataIPList(t.config.Filtering.KeepRdataFile)
		if err != nil {
			return fmt.Errorf("unable to open rdata ip file: %w", err)
		}
		t.LogInfo("loaded with %d rdata ip to the keep list", read)
	}
	return nil
}

func (t *FilteringTransform) LoadDomainsList() error {
	// before to start, reset all maps
	for key := range t.listFqdns {
		delete(t.listFqdns, key)
	}
	for key := range t.listDomainsRegex {
		delete(t.listDomainsRegex, key)
	}
	for key := range t.listKeepFqdns {
		delete(t.listKeepFqdns, key)
	}
	for key := range t.listKeepDomainsRegex {
		delete(t.listKeepDomainsRegex, key)
	}

	if len(t.config.Filtering.DropFqdnFile) > 0 {
		file, err := os.Open(t.config.Filtering.DropFqdnFile)
		if err != nil {
			return fmt.Errorf("unable to open fqdn file: %w", err)
		} else {

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				fqdn := strings.ToLower(scanner.Text())
				t.listFqdns[fqdn] = true
			}
			t.LogInfo("loaded with %d fqdn to the drop list", len(t.listFqdns))
		}

	}

	if len(t.config.Filtering.DropDomainFile) > 0 {
		file, err := os.Open(t.config.Filtering.DropDomainFile)
		if err != nil {
			return fmt.Errorf("unable to open regex list file: %w", err)
		} else {

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				domain := strings.ToLower(scanner.Text())
				t.listDomainsRegex[domain] = regexp.MustCompile(domain)
			}
			t.LogInfo("loaded with %d domains to the drop list", len(t.listDomainsRegex))
		}
	}

	if len(t.config.Filtering.KeepFqdnFile) > 0 {
		file, err := os.Open(t.config.Filtering.KeepFqdnFile)
		if err != nil {
			return fmt.Errorf("unable to open KeepFqdnFile file: %w", err)
		} else {
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				keepDomain := strings.ToLower(scanner.Text())
				t.listKeepFqdns[keepDomain] = true
			}
			t.LogInfo("loaded with %d fqdn(s) to the keep list", len(t.listKeepFqdns))
		}
	}

	if len(t.config.Filtering.KeepDomainFile) > 0 {
		file, err := os.Open(t.config.Filtering.KeepDomainFile)
		if err != nil {
			return fmt.Errorf("unable to open KeepDomainFile file: %w", err)
		} else {
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				keepDomain := strings.ToLower(scanner.Text())
				t.listKeepDomainsRegex[keepDomain] = regexp.MustCompile(keepDomain)
			}
			t.LogInfo("loaded with %d domains to the keep list", len(t.listKeepDomainsRegex))
		}
	}
	return nil
}

func (t *FilteringTransform) loadQueryIPList(fname string, drop bool) (uint64, error) {
	var emptyIPSet *netaddr.IPSet
	t.ipsetDrop = emptyIPSet
	t.ipsetKeep = emptyIPSet

	file, err := os.Open(fname)
	if err != nil {
		return 0, err
	}

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
				t.LogError("%s in in %s is neither an IP address nor a prefix", ipOrPrefix, fname)
				continue
			}
			ipsetbuilder.Add(ip)
			continue
		}
		ipsetbuilder.AddPrefix(prefix)
	}

	file.Close()

	if drop {
		t.ipsetDrop, err = ipsetbuilder.IPSet()
	} else {
		t.ipsetKeep, err = ipsetbuilder.IPSet()
	}

	return read, err
}

func (t *FilteringTransform) loadKeepRdataIPList(fname string) (uint64, error) {
	var emptyIPSet *netaddr.IPSet
	t.rDataIpsetKeep = emptyIPSet

	file, err := os.Open(fname)
	if err != nil {
		return 0, err
	}

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
				t.LogError("%s in in %s is neither an IP address nor a prefix", ipOrPrefix, fname)
				continue
			}
			ipsetbuilder.Add(ip)
			continue
		}
		ipsetbuilder.AddPrefix(prefix)
	}

	file.Close()

	t.rDataIpsetKeep, err = ipsetbuilder.IPSet()

	return read, err
}

func (t *FilteringTransform) dropQueryFilter(dm *dnsutils.DNSMessage) (int, error) {
	if dm.DNS.Type == dnsutils.DNSQuery {
		return ReturnDrop, nil
	}
	return ReturnKeep, nil
}

func (t *FilteringTransform) dropReplyFilter(dm *dnsutils.DNSMessage) (int, error) {
	if dm.DNS.Type == dnsutils.DNSReply {
		return ReturnDrop, nil
	}
	return ReturnKeep, nil
}

func (t *FilteringTransform) dropRCodeFilter(dm *dnsutils.DNSMessage) (int, error) {
	// drop according to the rcode ?
	if _, ok := t.mapRcodes[dm.DNS.Rcode]; ok {
		return ReturnDrop, nil
	}
	return ReturnKeep, nil
}

func (t *FilteringTransform) keepQueryIPFilter(dm *dnsutils.DNSMessage) (int, error) {
	ip, _ := netaddr.ParseIP(dm.NetworkInfo.QueryIP)
	if t.ipsetKeep.Contains(ip) {
		return ReturnKeep, nil
	}
	return ReturnDrop, nil
}

func (t *FilteringTransform) dropQueryIPFilter(dm *dnsutils.DNSMessage) (int, error) {
	ip, _ := netaddr.ParseIP(dm.NetworkInfo.QueryIP)
	if t.ipsetDrop.Contains(ip) {
		return ReturnDrop, nil
	}
	return ReturnKeep, nil
}

func (t *FilteringTransform) keepRdataFilter(dm *dnsutils.DNSMessage) (int, error) {
	if len(dm.DNS.DNSRRs.Answers) > 0 {
		// If even one exists in filter list then pass through filter
		for _, answer := range dm.DNS.DNSRRs.Answers {
			if answer.Rdatatype == "A" || answer.Rdatatype == "AAAA" {
				ip, _ := netaddr.ParseIP(answer.Rdata)
				if t.rDataIpsetKeep.Contains(ip) {
					return ReturnKeep, nil
				}
			}
		}
	}
	return ReturnDrop, nil
}

func (t *FilteringTransform) dropFqdnFilter(dm *dnsutils.DNSMessage) (int, error) {
	if _, ok := t.listFqdns[dm.DNS.Qname]; ok {
		return ReturnDrop, nil
	}
	return ReturnKeep, nil
}

func (t *FilteringTransform) dropDomainRegexFilter(dm *dnsutils.DNSMessage) (int, error) {
	// partial fqdn with regexp
	for _, d := range t.listDomainsRegex {
		if d.MatchString(dm.DNS.Qname) {
			return ReturnDrop, nil
		}
	}
	return ReturnKeep, nil
}

func (t *FilteringTransform) keepFqdnFilter(dm *dnsutils.DNSMessage) (int, error) {
	if _, ok := t.listKeepFqdns[dm.DNS.Qname]; ok {
		return ReturnKeep, nil
	}
	return ReturnDrop, nil
}

func (t *FilteringTransform) keepDomainRegexFilter(dm *dnsutils.DNSMessage) (int, error) {
	// partial fqdn with regexp
	for _, d := range t.listKeepDomainsRegex {
		if d.MatchString(dm.DNS.Qname) {
			return ReturnKeep, nil
		}
	}
	return ReturnDrop, nil
}

// drop all except every nth entry
func (t *FilteringTransform) downsampleFilter(dm *dnsutils.DNSMessage) (int, error) {
	if dm.Filtering == nil {
		dm.Filtering = &dnsutils.TransformFiltering{}
	}

	// Increment the downsampleCount for each processed DNS message.
	t.downsampleCount += 1

	// Calculate the remainder once and add sampling rate to DNS message
	remainder := t.downsampleCount % t.downsample
	if dm.Filtering != nil {
		dm.Filtering.SampleRate = t.downsample
	}

	switch remainder {
	// If the remainder is zero, reset the downsampleCount to 0 and drop the DNS message by returning false.
	case 0:
		t.downsampleCount = 0
		return ReturnDrop, nil

	// If the remainder is not zero, keep the DNS message and return true.
	default:
		return ReturnKeep, nil
	}
}
