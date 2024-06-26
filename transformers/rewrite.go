package transformers

import (
	"errors"
	"reflect"
	"strings"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

type RewriteTransform struct {
	GenericTransformer
}

func NewRewriteTransform(config *pkgconfig.ConfigTransformers, logger *logger.Logger, name string, instance int, nextWorkers []chan dnsutils.DNSMessage) *RewriteTransform {
	t := &RewriteTransform{GenericTransformer: NewTransformer(config, logger, "rewrite", name, instance, nextWorkers)}
	return t
}

func (t *RewriteTransform) GetTransforms() ([]Subtransform, error) {
	subtransforms := []Subtransform{}
	if len(t.config.Rewrite.Identifiers) > 0 {
		subtransforms = append(subtransforms, Subtransform{name: "rewrite", processFunc: t.UpdateValues})
	}
	return subtransforms, nil
}

func (t *RewriteTransform) UpdateValues(dm *dnsutils.DNSMessage) (int, error) {
	dmValue := reflect.ValueOf(dm)
	if dmValue.Kind() == reflect.Ptr {
		dmValue = dmValue.Elem()
	}

	for nestedKeys, value := range t.config.Rewrite.Identifiers {
		realValue, found := getFieldByTag(dmValue, nestedKeys)
		switch {
		case !found:
			return 0, errors.New("field not found: " + nestedKeys)
		case !realValue.CanSet():
			return 0, errors.New("field cannot be set: " + nestedKeys)
		default:
			newValue := reflect.ValueOf(value)
			if realValue.Kind() == newValue.Kind() {
				realValue.Set(newValue)
			} else {
				return 0, errors.New("type mismatch: unable to set the value for " + nestedKeys)
			}
		}
	}

	return ReturnKeep, nil
}

func getFieldByTag(value reflect.Value, nestedKeys string) (reflect.Value, bool) {
	listKeys := strings.SplitN(nestedKeys, ".", 2)

	for j, jsonKey := range listKeys {
		// Iterate over the fields of the structure
		for i := 0; i < value.NumField(); i++ {
			field := value.Type().Field(i)

			// Get JSON tag
			tag := field.Tag.Get("json")
			tagClean := strings.TrimSuffix(tag, ",omitempty")

			// Check if the JSON tag matches
			if tagClean == jsonKey {
				switch field.Type.Kind() {
				// ptr
				case reflect.Ptr:
					if fieldValue, found := getFieldByTag(value.Field(i).Elem(), listKeys[j+1]); found {
						return fieldValue, true
					}

				// struct
				case reflect.Struct:
					if fieldValue, found := getFieldByTag(value.Field(i), listKeys[j+1]); found {
						return fieldValue, true
					}
				// int, string
				default:
					return value.Field(i), true
				}
			}
		}
	}

	return reflect.Value{}, false
}
