package dnsutils

func (dm *DNSMessage) ApplyRelabeling(dnsFields map[string]interface{}) error {

	for _, label := range dm.Relabeling.Rules {
		regex := label.Regex
		for key := range dnsFields {
			if regex.MatchString(key) {
				if label.Action == "rename" {
					replacement := label.Replacement
					if value, exists := dnsFields[replacement]; exists {
						switch v := value.(type) {
						case []string:
							dnsFields[replacement] = append(v, ConvertToString(dnsFields[key]))
						default:
							dnsFields[replacement] = []string{ConvertToString(v), ConvertToString(dnsFields[key])}
						}
					} else {
						dnsFields[replacement] = ConvertToString(dnsFields[key])
					}
				}

				// delete on all case
				delete(dnsFields, key)
			}
		}
	}

	return nil
}
