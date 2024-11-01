package dnsutils

import "github.com/flosch/pongo2"

func (dm *DNSMessage) ToTextTemplate(template string) (string, error) {
	context := pongo2.Context{"dm": dm}

	// Parse and execute the template
	tmpl, err := pongo2.FromString(template)
	if err != nil {
		return "", err
	}

	result, err := tmpl.Execute(context)
	if err != nil {
		return "", err
	}
	return result, nil
}
