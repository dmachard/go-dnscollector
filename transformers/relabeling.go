package transformers

import (
	"regexp"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

type RelabelTransform struct {
	GenericTransformer
	RelabelingRules []dnsutils.RelabelingRule
}

func NewRelabelTransform(config *pkgconfig.ConfigTransformers, logger *logger.Logger, name string, instance int, nextWorkers []chan dnsutils.DNSMessage) *RelabelTransform {
	t := &RelabelTransform{GenericTransformer: NewTransformer(config, logger, "relabeling", name, instance, nextWorkers)}
	return t
}

func (t *RelabelTransform) GetTransforms() []Subtransform {
	subprocessors := []Subtransform{}
	if len(t.config.Relabeling.Rename) > 0 || len(t.config.Relabeling.Remove) > 0 {
		actions := t.Precompile()
		subprocessors = append(subprocessors, Subtransform{name: "relabeling:" + actions, processFunc: t.AddRules})
	}
	return subprocessors
}

// Pre-compile regular expressions
func (t *RelabelTransform) Precompile() string {
	action_rename := false
	action_drop := false
	for _, label := range t.config.Relabeling.Rename {
		t.RelabelingRules = append(t.RelabelingRules, dnsutils.RelabelingRule{
			Regex:       regexp.MustCompile(label.Regex),
			Replacement: label.Replacement,
			Action:      "rename",
		})
		action_rename = true
	}
	for _, label := range t.config.Relabeling.Remove {
		t.RelabelingRules = append(t.RelabelingRules, dnsutils.RelabelingRule{
			Regex:       regexp.MustCompile(label.Regex),
			Replacement: label.Replacement,
			Action:      "drop",
		})
		action_drop = true
	}

	if action_rename && action_drop {
		return "rename+remove"
	}
	if action_rename && !action_drop {
		return "rename"
	}
	if !action_rename && action_drop {
		return "remove"
	}
	return "error"
}

func (t *RelabelTransform) AddRules(dm *dnsutils.DNSMessage) int {
	if dm.Relabeling == nil {
		dm.Relabeling = &dnsutils.TransformRelabeling{
			Rules: t.RelabelingRules,
		}
	}
	return ReturnSuccess
}
