package dnsutils

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	OtelDirectives            = regexp.MustCompile(`^otel-*`)
	PdnsDirectives            = regexp.MustCompile(`^powerdns-*`)
	GeoIPDirectives           = regexp.MustCompile(`^geoip-*`)
	SuspiciousDirectives      = regexp.MustCompile(`^suspicious-*`)
	PublicSuffixDirectives    = regexp.MustCompile(`^publixsuffix-*`)
	ExtractedDirectives       = regexp.MustCompile(`^extracted-*`)
	ReducerDirectives         = regexp.MustCompile(`^reducer-*`)
	MachineLearningDirectives = regexp.MustCompile(`^ml-*`)
	FilteringDirectives       = regexp.MustCompile(`^filtering-*`)
	RawTextDirective          = regexp.MustCompile(`^ *\{.*\}`)
	ATagsDirectives           = regexp.MustCompile(`^atags*`)
)

func (dm *DNSMessage) handleOpenTelemetryDirectives(directive string, s *strings.Builder) error {
	if dm.OpenTelemetry == nil {
		s.WriteString("-")
	} else {
		switch {
		case directive == "otel-trace-id":
			s.WriteString(dm.OpenTelemetry.TraceID)
		default:
			return errors.New(ErrorUnexpectedDirective + directive)
		}
	}
	return nil
}

func (dm *DNSMessage) handleGeoIPDirectives(directive string, s *strings.Builder) error {
	if dm.Geo == nil {
		s.WriteString("-")
	} else {
		switch {
		case directive == "geoip-continent":
			s.WriteString(dm.Geo.Continent)
		case directive == "geoip-country":
			s.WriteString(dm.Geo.CountryIsoCode)
		case directive == "geoip-city":
			s.WriteString(dm.Geo.City)
		case directive == "geoip-as-number":
			s.WriteString(dm.Geo.AutonomousSystemNumber)
		case directive == "geoip-as-owner":
			s.WriteString(dm.Geo.AutonomousSystemOrg)
		default:
			return errors.New(ErrorUnexpectedDirective + directive)
		}
	}
	return nil
}

func (dm *DNSMessage) handlePdnsDirectives(directive string, s *strings.Builder) error {
	if dm.PowerDNS == nil {
		s.WriteString("-")
	} else {
		var directives []string
		if i := strings.IndexByte(directive, ':'); i == -1 {
			directives = append(directives, directive)
		} else {
			directives = []string{directive[:i], directive[i+1:]}
		}

		switch directive := directives[0]; {
		case directive == "powerdns-tags":
			if dm.PowerDNS.Tags == nil {
				s.WriteString("-")
			} else {
				if len(dm.PowerDNS.Tags) > 0 {
					if len(directives) == 2 {
						tagIndex, err := strconv.Atoi(directives[1])
						if err != nil {
							log.Fatalf("unsupport tag index provided (integer expected): %s", directives[1])
						}
						if tagIndex >= len(dm.PowerDNS.Tags) {
							s.WriteString("-")
						} else {
							s.WriteString(dm.PowerDNS.Tags[tagIndex])
						}
					} else {
						for i, tag := range dm.PowerDNS.Tags {
							s.WriteString(tag)
							// add separator
							if i+1 < len(dm.PowerDNS.Tags) {
								s.WriteString(",")
							}
						}
					}
				} else {
					s.WriteString("-")
				}
			}
		case directive == "powerdns-applied-policy":
			if len(dm.PowerDNS.AppliedPolicy) > 0 {
				s.WriteString(dm.PowerDNS.AppliedPolicy)
			} else {
				s.WriteString("-")
			}
		case directive == "powerdns-applied-policy-hit":
			if len(dm.PowerDNS.AppliedPolicyHit) > 0 {
				s.WriteString(dm.PowerDNS.AppliedPolicyHit)
			} else {
				s.WriteString("-")
			}
		case directive == "powerdns-applied-policy-kind":
			if len(dm.PowerDNS.AppliedPolicyKind) > 0 {
				s.WriteString(dm.PowerDNS.AppliedPolicyKind)
			} else {
				s.WriteString("-")
			}
		case directive == "powerdns-applied-policy-trigger":
			if len(dm.PowerDNS.AppliedPolicyTrigger) > 0 {
				s.WriteString(dm.PowerDNS.AppliedPolicyTrigger)
			} else {
				s.WriteString("-")
			}
		case directive == "powerdns-applied-policy-type":
			if len(dm.PowerDNS.AppliedPolicyType) > 0 {
				s.WriteString(dm.PowerDNS.AppliedPolicyType)
			} else {
				s.WriteString("-")
			}
		case directive == "powerdns-requestor-id":
			if len(dm.PowerDNS.RequestorID) > 0 {
				s.WriteString(dm.PowerDNS.RequestorID)
			} else {
				s.WriteString("-")
			}
		case directive == "powerdns-device-id":
			if len(dm.PowerDNS.DeviceID) > 0 {
				s.WriteString(dm.PowerDNS.DeviceID)
			} else {
				s.WriteString("-")
			}
		case directive == "powerdns-device-name":
			if len(dm.PowerDNS.DeviceName) > 0 {
				s.WriteString(dm.PowerDNS.DeviceName)
			} else {
				s.WriteString("-")
			}
		case directive == "powerdns-message-id":
			if len(dm.PowerDNS.MessageID) > 0 {
				s.WriteString(dm.PowerDNS.MessageID)
			} else {
				s.WriteString("-")
			}
		case directive == "powerdns-initial-requestor-id":
			if len(dm.PowerDNS.InitialRequestorID) > 0 {
				s.WriteString(dm.PowerDNS.InitialRequestorID)
			} else {
				s.WriteString("-")
			}
		case directive == "powerdns-original-request-subnet":
			if len(dm.PowerDNS.OriginalRequestSubnet) > 0 {
				s.WriteString(dm.PowerDNS.OriginalRequestSubnet)
			} else {
				s.WriteString("-")
			}
		case directive == "powerdns-metadata":
			if dm.PowerDNS.Metadata == nil {
				s.WriteString("-")
			} else {
				if len(dm.PowerDNS.Metadata) > 0 && len(directives) == 2 {
					if metaValue, ok := dm.PowerDNS.Metadata[directives[1]]; ok {
						if len(metaValue) > 0 {
							s.WriteString(strings.ReplaceAll(metaValue, " ", "_"))
						} else {
							s.WriteString("-")
						}
					} else {
						s.WriteString("-")
					}
				} else {
					s.WriteString("-")
				}
			}
		case directive == "powerdns-http-version":
			if len(dm.PowerDNS.HTTPVersion) > 0 {
				s.WriteString(dm.PowerDNS.HTTPVersion)
			} else {
				s.WriteString("-")
			}
		default:
			return errors.New(ErrorUnexpectedDirective + directive)
		}
	}
	return nil
}

func (dm *DNSMessage) handleATagsDirectives(directive string, s *strings.Builder) error {
	if dm.ATags == nil {
		s.WriteString("-")
	} else {
		var directives []string
		if i := strings.IndexByte(directive, ':'); i == -1 {
			directives = append(directives, directive)
		} else {
			directives = []string{directive[:i], directive[i+1:]}
		}

		switch directive := directives[0]; {
		case directive == "atags":
			if len(dm.ATags.Tags) > 0 {
				if len(directives) == 2 {
					tagIndex, err := strconv.Atoi(directives[1])
					if err != nil {
						log.Fatalf("unsupport tag index provided (integer expected): %s", directives[1])
					}
					if tagIndex >= len(dm.ATags.Tags) {
						s.WriteString("-")
					} else {
						s.WriteString(dm.ATags.Tags[tagIndex])
					}
				} else {
					for i, tag := range dm.ATags.Tags {
						s.WriteString(tag)
						// add separator
						if i+1 < len(dm.ATags.Tags) {
							s.WriteString(",")
						}
					}
				}
			} else {
				s.WriteString("-")
			}
		default:
			return errors.New(ErrorUnexpectedDirective + directive)
		}
	}
	return nil
}

func (dm *DNSMessage) handleSuspiciousDirectives(directive string, s *strings.Builder) error {
	if dm.Suspicious == nil {
		s.WriteString("-")
	} else {
		switch {
		case directive == "suspicious-score":
			s.WriteString(strconv.Itoa(int(dm.Suspicious.Score)))
		default:
			return errors.New(ErrorUnexpectedDirective + directive)
		}
	}
	return nil
}

func (dm *DNSMessage) handlePublicSuffixDirectives(directive string, s *strings.Builder) error {
	if dm.PublicSuffix == nil {
		s.WriteString("-")
	} else {
		switch {
		case directive == "publixsuffix-tld":
			s.WriteString(dm.PublicSuffix.QnamePublicSuffix)
		case directive == "publixsuffix-etld+1":
			s.WriteString(dm.PublicSuffix.QnameEffectiveTLDPlusOne)
		case directive == "publixsuffix-managed-icann":
			if dm.PublicSuffix.ManagedByICANN {
				s.WriteString("managed")
			} else {
				s.WriteString("private")
			}
		default:
			return errors.New(ErrorUnexpectedDirective + directive)
		}
	}
	return nil
}

func (dm *DNSMessage) handleExtractedDirectives(directive string, s *strings.Builder) error {
	if dm.Extracted == nil {
		s.WriteString("-")
		return nil
	}
	switch {
	case directive == "extracted-dns-payload":
		if len(dm.DNS.Payload) > 0 {
			dst := make([]byte, base64.StdEncoding.EncodedLen(len(dm.DNS.Payload)))
			base64.StdEncoding.Encode(dst, dm.DNS.Payload)
			s.Write(dst)
		} else {
			s.WriteString("-")
		}
	default:
		return errors.New(ErrorUnexpectedDirective + directive)
	}
	return nil
}

func (dm *DNSMessage) handleFilteringDirectives(directive string, s *strings.Builder) error {
	if dm.Filtering == nil {
		s.WriteString("-")
	} else {
		switch {
		case directive == "filtering-sample-rate":
			s.WriteString(strconv.Itoa(dm.Filtering.SampleRate))
		default:
			return errors.New(ErrorUnexpectedDirective + directive)
		}
	}
	return nil
}

func (dm *DNSMessage) handleReducerDirectives(directive string, s *strings.Builder) error {
	if dm.Reducer == nil {
		s.WriteString("-")
	} else {
		switch {
		case directive == "reducer-occurrences":
			s.WriteString(strconv.Itoa(dm.Reducer.Occurrences))
		case directive == "reducer-cumulative-length":
			s.WriteString(strconv.Itoa(dm.Reducer.CumulativeLength))
		default:
			return errors.New(ErrorUnexpectedDirective + directive)
		}
	}
	return nil
}

func (dm *DNSMessage) handleMachineLearningDirectives(directive string, s *strings.Builder) error {
	if dm.MachineLearning == nil {
		s.WriteString("-")
	} else {
		switch {
		case directive == "ml-entropy":
			s.WriteString(strconv.FormatFloat(dm.MachineLearning.Entropy, 'f', -1, 64))
		case directive == "ml-length":
			s.WriteString(strconv.Itoa(dm.MachineLearning.Length))
		case directive == "ml-digits":
			s.WriteString(strconv.Itoa(dm.MachineLearning.Digits))
		case directive == "ml-lowers":
			s.WriteString(strconv.Itoa(dm.MachineLearning.Lowers))
		case directive == "ml-uppers":
			s.WriteString(strconv.Itoa(dm.MachineLearning.Uppers))
		case directive == "ml-specials":
			s.WriteString(strconv.Itoa(dm.MachineLearning.Specials))
		case directive == "ml-others":
			s.WriteString(strconv.Itoa(dm.MachineLearning.Others))
		case directive == "ml-labels":
			s.WriteString(strconv.Itoa(dm.MachineLearning.Labels))
		case directive == "ml-ratio-digits":
			s.WriteString(strconv.FormatFloat(dm.MachineLearning.RatioDigits, 'f', 3, 64))
		case directive == "ml-ratio-letters":
			s.WriteString(strconv.FormatFloat(dm.MachineLearning.RatioLetters, 'f', 3, 64))
		case directive == "ml-ratio-specials":
			s.WriteString(strconv.FormatFloat(dm.MachineLearning.RatioSpecials, 'f', 3, 64))
		case directive == "ml-ratio-others":
			s.WriteString(strconv.FormatFloat(dm.MachineLearning.RatioOthers, 'f', 3, 64))
		case directive == "ml-consecutive-chars":
			s.WriteString(strconv.Itoa(dm.MachineLearning.ConsecutiveChars))
		case directive == "ml-consecutive-vowels":
			s.WriteString(strconv.Itoa(dm.MachineLearning.ConsecutiveVowels))
		case directive == "ml-consecutive-digits":
			s.WriteString(strconv.Itoa(dm.MachineLearning.ConsecutiveDigits))
		case directive == "ml-consecutive-consonants":
			s.WriteString(strconv.Itoa(dm.MachineLearning.ConsecutiveConsonants))
		case directive == "ml-size":
			s.WriteString(strconv.Itoa(dm.MachineLearning.Size))
		case directive == "ml-occurrences":
			s.WriteString(strconv.Itoa(dm.MachineLearning.Occurrences))
		case directive == "ml-uncommon-qtypes":
			s.WriteString(strconv.Itoa(dm.MachineLearning.UncommonQtypes))
		default:
			return errors.New(ErrorUnexpectedDirective + directive)
		}
	}
	return nil
}

func (dm *DNSMessage) Bytes(format []string, fieldDelimiter string, fieldBoundary string) []byte {
	line, err := dm.ToTextLine(format, fieldDelimiter, fieldBoundary)
	if err != nil {
		log.Fatalf("unsupport directive for text format: %s", err)
	}
	return line
}

func (dm *DNSMessage) String(format []string, fieldDelimiter string, fieldBoundary string) string {
	return string(dm.Bytes(format, fieldDelimiter, fieldBoundary))
}

func (dm *DNSMessage) ToTextLine(format []string, fieldDelimiter string, fieldBoundary string) ([]byte, error) {
	var s strings.Builder

	an := dm.DNS.DNSRRs.Answers
	qname := dm.DNS.Qname
	flags := dm.DNS.Flags

	for i, directive := range format {
		switch {
		case directive == "timestamp-rfc3339ns", directive == "timestamp":
			s.WriteString(dm.DNSTap.TimestampRFC3339)
		case directive == "timestamp-unixms":
			s.WriteString(fmt.Sprintf("%d", dm.DNSTap.Timestamp/1000000))
		case directive == "timestamp-unixus":
			s.WriteString(fmt.Sprintf("%d", dm.DNSTap.Timestamp/1000))
		case directive == "timestamp-unixns":
			s.WriteString(fmt.Sprintf("%d", dm.DNSTap.Timestamp))
		case directive == "localtime":
			ts := time.Unix(int64(dm.DNSTap.TimeSec), int64(dm.DNSTap.TimeNsec))
			s.WriteString(ts.Format("2006-01-02 15:04:05.999999999"))
		case directive == "qname":
			if len(qname) == 0 {
				s.WriteString(".")
			} else {
				QuoteStringAndWrite(&s, qname, fieldDelimiter, fieldBoundary)
			}
		case directive == "identity":
			if len(dm.DNSTap.Identity) == 0 {
				s.WriteString("-")
			} else {
				QuoteStringAndWrite(&s, dm.DNSTap.Identity, fieldDelimiter, fieldBoundary)
			}
		case directive == "peer-name":
			if len(dm.DNSTap.PeerName) == 0 {
				s.WriteString("-")
			} else {
				QuoteStringAndWrite(&s, dm.DNSTap.PeerName, fieldDelimiter, fieldBoundary)
			}
		case directive == "version":
			if len(dm.DNSTap.Version) == 0 {
				s.WriteString("-")
			} else {
				QuoteStringAndWrite(&s, dm.DNSTap.Version, fieldDelimiter, fieldBoundary)
			}
		case directive == "extra":
			s.WriteString(dm.DNSTap.Extra)
		case directive == "policy-rule":
			s.WriteString(dm.DNSTap.PolicyRule)
		case directive == "policy-type":
			s.WriteString(dm.DNSTap.PolicyType)
		case directive == "policy-action":
			s.WriteString(dm.DNSTap.PolicyAction)
		case directive == "policy-match":
			s.WriteString(dm.DNSTap.PolicyMatch)
		case directive == "policy-value":
			s.WriteString(dm.DNSTap.PolicyValue)
		case directive == "query-zone":
			s.WriteString(dm.DNSTap.QueryZone)
		case directive == "operation":
			s.WriteString(dm.DNSTap.Operation)
		case directive == "rcode":
			s.WriteString(dm.DNS.Rcode)
		case directive == "id":
			s.WriteString(strconv.Itoa(dm.DNS.ID))
		case directive == "queryip":
			s.WriteString(dm.NetworkInfo.QueryIP)
		case directive == "queryport":
			s.WriteString(dm.NetworkInfo.QueryPort)
		case directive == "responseip":
			s.WriteString(dm.NetworkInfo.ResponseIP)
		case directive == "responseport":
			s.WriteString(dm.NetworkInfo.ResponsePort)
		case directive == "family":
			s.WriteString(dm.NetworkInfo.Family)
		case directive == "protocol":
			s.WriteString(dm.NetworkInfo.Protocol)
		case directive == "length-unit":
			s.WriteString(strconv.Itoa(dm.DNS.Length) + "b")
		case directive == "length":
			s.WriteString(strconv.Itoa(dm.DNS.Length))
		case directive == "qtype":
			s.WriteString(dm.DNS.Qtype)
		case directive == "qclass":
			s.WriteString(dm.DNS.Qclass)
		case directive == "latency":
			s.WriteString(fmt.Sprintf("%.9f", dm.DNSTap.Latency))
		case directive == "malformed":
			if dm.DNS.MalformedPacket {
				s.WriteString("PKTERR")
			} else {
				s.WriteByte('-')
			}
		case directive == "qr":
			s.WriteString(dm.DNS.Type)
		case directive == "opcode":
			s.WriteString(strconv.Itoa(dm.DNS.Opcode))
		case directive == "tr":
			if dm.NetworkInfo.TCPReassembled {
				s.WriteString("TR")
			} else {
				s.WriteByte('-')
			}
		case directive == "df":
			if dm.NetworkInfo.IPDefragmented {
				s.WriteString("DF")
			} else {
				s.WriteByte('-')
			}
		case directive == "tc":
			if flags.TC {
				s.WriteString("TC")
			} else {
				s.WriteByte('-')
			}
		case directive == "aa":
			if flags.AA {
				s.WriteString("AA")
			} else {
				s.WriteByte('-')
			}
		case directive == "ra":
			if flags.RA {
				s.WriteString("RA")
			} else {
				s.WriteByte('-')
			}
		case directive == "ad":
			if flags.AD {
				s.WriteString("AD")
			} else {
				s.WriteByte('-')
			}
		case directive == "rd":
			if flags.RD {
				s.WriteString("RD")
			} else {
				s.WriteByte('-')
			}
		case directive == "ttl":
			if len(an) > 0 {
				s.WriteString(strconv.Itoa(an[0].TTL))
			} else {
				s.WriteByte('-')
			}
		case directive == "answer":
			if len(an) > 0 {
				s.WriteString(an[0].Rdata)
			} else {
				s.WriteByte('-')
			}

		case directive == "questionscount" || directive == "qdcount":
			s.WriteString(strconv.Itoa(dm.DNS.QdCount))
		case directive == "answercount" || directive == "ancount":
			s.WriteString(strconv.Itoa(dm.DNS.AnCount))
		case directive == "nscount":
			s.WriteString(strconv.Itoa(dm.DNS.NsCount))
		case directive == "arcount":
			s.WriteString(strconv.Itoa(dm.DNS.ArCount))

		case directive == "edns-csubnet":
			if len(dm.EDNS.Options) > 0 {
				for _, opt := range dm.EDNS.Options {
					if opt.Name == "CSUBNET" {
						s.WriteString(opt.Data)
						break
					}
				}
			} else {
				s.WriteByte('-')
			}

		// more directives from loggers
		case OtelDirectives.MatchString(directive):
			err := dm.handleOpenTelemetryDirectives(directive, &s)
			if err != nil {
				return nil, err
			}

		// more directives from collectors
		case PdnsDirectives.MatchString(directive):
			err := dm.handlePdnsDirectives(directive, &s)
			if err != nil {
				return nil, err
			}

		// more directives from transformers
		case ReducerDirectives.MatchString(directive):
			err := dm.handleReducerDirectives(directive, &s)
			if err != nil {
				return nil, err
			}
		case GeoIPDirectives.MatchString(directive):
			err := dm.handleGeoIPDirectives(directive, &s)
			if err != nil {
				return nil, err
			}
		case SuspiciousDirectives.MatchString(directive):
			err := dm.handleSuspiciousDirectives(directive, &s)
			if err != nil {
				return nil, err
			}
		case PublicSuffixDirectives.MatchString(directive):
			err := dm.handlePublicSuffixDirectives(directive, &s)
			if err != nil {
				return nil, err
			}
		case ExtractedDirectives.MatchString(directive):
			err := dm.handleExtractedDirectives(directive, &s)
			if err != nil {
				return nil, err
			}
		case MachineLearningDirectives.MatchString(directive):
			err := dm.handleMachineLearningDirectives(directive, &s)
			if err != nil {
				return nil, err
			}
		case FilteringDirectives.MatchString(directive):
			err := dm.handleFilteringDirectives(directive, &s)
			if err != nil {
				return nil, err
			}
		case ATagsDirectives.MatchString(directive):
			err := dm.handleATagsDirectives(directive, &s)
			if err != nil {
				return nil, err
			}
		case RawTextDirective.MatchString(directive):
			directive = strings.ReplaceAll(directive, "{", "")
			directive = strings.ReplaceAll(directive, "}", "")
			s.WriteString(directive)

		// handle invalid directive
		default:
			return nil, errors.New(ErrorUnexpectedDirective + directive)
		}

		if i < len(format)-1 {
			if len(fieldDelimiter) > 0 {
				s.WriteString(fieldDelimiter)
			}
		}
	}
	return []byte(s.String()), nil
}
