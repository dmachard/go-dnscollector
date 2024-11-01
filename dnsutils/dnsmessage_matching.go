package dnsutils

import (
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

func (dm *DNSMessage) Matching(matching map[string]interface{}) (error, bool) {
	if len(matching) == 0 {
		return nil, false
	}

	dmValue := reflect.ValueOf(dm)

	if dmValue.Kind() == reflect.Ptr {
		dmValue = dmValue.Elem()
	}

	var isMatch = true

	for nestedKeys, value := range matching {
		realValue, found := getFieldByJSONTag(dmValue, nestedKeys)
		if !found {
			return nil, false
		}

		expectedValue := reflect.ValueOf(value)
		switch expectedValue.Kind() {
		// integer
		case reflect.Int:
			match, err := matchUserInteger(realValue, expectedValue)
			if err != nil {
				return err, false
			}
			if !match {
				return nil, false
			}

		// string
		case reflect.String:
			match, err := matchUserPattern(realValue, expectedValue)
			if err != nil {
				return err, false
			}
			if !match {
				return nil, false
			}

		// bool
		case reflect.Bool:
			match, err := matchUserBoolean(realValue, expectedValue)
			if err != nil {
				return err, false
			}
			if !match {
				return nil, false
			}

		// map
		case reflect.Map:
			match, err := matchUserMap(realValue, expectedValue)
			if err != nil {
				return err, false
			}
			if !match {
				return nil, false
			}

		// list/slice
		case reflect.Slice:
			match, err := matchUserSlice(realValue, expectedValue)
			if err != nil {
				return err, false
			}
			if !match {
				return nil, false
			}

		// other user types
		default:
			return fmt.Errorf("unsupported type value: %s", expectedValue.Kind()), false
		}

	}

	return nil, isMatch
}

// matchUserMap matches a map based on user-provided conditions.
// dns.qname:
// match-source: "file://./tests/testsdata/filtering_keep_domains_regex.txt"
// source-kind: "regexp_list"
func matchUserMap(realValue, expectedValue reflect.Value) (bool, error) {
	for _, opKey := range expectedValue.MapKeys() {
		opValue := expectedValue.MapIndex(opKey)
		opName := opKey.Interface().(string)

		switch opName {
		// Integer great than ?
		case MatchingOpGreaterThan:

			isFloat, isInt := false, false
			if _, ok := opValue.Interface().(float64); ok {
				isFloat = true
			}
			if _, ok := opValue.Interface().(int); ok {
				isInt = true
			}

			if !isFloat && !isInt {
				return false, fmt.Errorf("integer or float is expected for greater-than operator, not %s", reflect.TypeOf(opValue.Interface()))
			}

			// If realValue is a slice
			if realValue.Kind() == reflect.Slice {
				for i := 0; i < realValue.Len(); i++ {
					elemValue := realValue.Index(i)

					// Check if the element is a int
					if _, ok := elemValue.Interface().(int); !ok {
						continue
					}

					// Check for match
					if elemValue.Interface().(int) > opValue.Interface().(int) {
						return true, nil
					}
				}
				return false, nil
			}

			if isFloat && realValue.Kind() == reflect.Float64 {
				if realValue.Interface().(float64) > opValue.Interface().(float64) {
					return true, nil
				}
			}

			if isInt && realValue.Kind() == reflect.Int {
				if realValue.Interface().(int) > opValue.Interface().(int) {
					return true, nil
				}
			}

			return false, nil

		// Integer lower than ?
		case MatchingOpLowerThan:
			isFloat, isInt := false, false
			if _, ok := opValue.Interface().(float64); ok {
				isFloat = true
			}
			if _, ok := opValue.Interface().(int); ok {
				isInt = true
			}

			if !isFloat && !isInt {
				return false, fmt.Errorf("integer or float is expected for lower-than operator, not %s", reflect.TypeOf(opValue.Interface()))
			}

			// If realValue is a slice
			if realValue.Kind() == reflect.Slice {
				for i := 0; i < realValue.Len(); i++ {
					elemValue := realValue.Index(i)

					// Check if the element is a int
					if _, ok := elemValue.Interface().(int); !ok {
						continue
					}

					// Check for match
					if elemValue.Interface().(int) < opValue.Interface().(int) {
						return true, nil
					}
				}
				return false, nil
			}

			if isFloat && realValue.Kind() == reflect.Float64 {
				if realValue.Interface().(float64) < opValue.Interface().(float64) {
					return true, nil
				}
			}

			if isInt && realValue.Kind() == reflect.Int {
				if realValue.Interface().(int) < opValue.Interface().(int) {
					return true, nil
				}
			}

			return false, nil

		// Ignore these operators
		case MatchingOpSource, MatchingOpSourceKind:
			continue

		// List of pattern
		case MatchingKindRegexp:
			patternList := opValue.Interface().([]*regexp.Regexp)

			// If realValue is a slice
			if realValue.Kind() == reflect.Slice {
				for i := 0; i < realValue.Len(); i++ {
					elemValue := realValue.Index(i)

					// Check if the element is a string
					if _, ok := elemValue.Interface().(string); !ok {
						continue
					}

					// Check for a match with the regex pattern
					for _, pattern := range patternList {
						if pattern.MatchString(elemValue.Interface().(string)) {
							return true, nil
						}
					}
				}
				// No match found in the slice
				return false, nil
			}

			if realValue.Kind() != reflect.String {
				return false, nil
			}
			for _, pattern := range patternList {
				if pattern.MatchString(realValue.Interface().(string)) {
					return true, nil
				}
			}
			// No match found in pattern list
			return false, nil

		// List of string
		case MatchingKindString:
			stringList := opValue.Interface().([]string)

			// If realValue is a slice
			if realValue.Kind() == reflect.Slice {
				for i := 0; i < realValue.Len(); i++ {
					elemValue := realValue.Index(i)

					// Check if the element is a string
					if _, ok := elemValue.Interface().(string); !ok {
						continue
					}

					// Check for a match with the text
					for _, textItem := range stringList {
						if textItem == realValue.Interface().(string) {
							return true, nil
						}
					}
				}
				// No match found in the slice
				return false, nil
			}

			if realValue.Kind() != reflect.String {
				return false, nil
			}
			for _, textItem := range stringList {
				if textItem == realValue.Interface().(string) {
					return true, nil
				}
			}

			// No match found in string list
			return false, nil

		default:
			return false, fmt.Errorf("invalid operator '%s', ignore it", opKey.Interface().(string))
		}
	}
	return true, nil
}

// matchUserSlice matches a slice based on user-provided conditions.
// dns.qname:
//   - ".*\\.github\\.com$"
//   - "^www\\.google\\.com$"
func matchUserSlice(realValue, expectedValue reflect.Value) (bool, error) {
	match := false
	for i := 0; i < expectedValue.Len() && !match; i++ {
		reflectedSub := reflect.ValueOf(expectedValue.Index(i).Interface())

		switch reflectedSub.Kind() {
		case reflect.Int:
			if realValue.Kind() == reflect.Slice {
				for i := 0; i < realValue.Len(); i++ {
					elemValue := realValue.Index(i)
					if _, ok := elemValue.Interface().(int); !ok {
						continue
					}
					if reflectedSub.Interface().(int) == elemValue.Interface().(int) {
						return true, nil
					}
				}
			}

			if realValue.Kind() != reflect.Int || realValue.Interface().(int) != reflectedSub.Interface().(int) {
				continue
			}
			match = true
		case reflect.String:
			pattern := regexp.MustCompile(reflectedSub.Interface().(string))
			if realValue.Kind() == reflect.Slice {
				for i := 0; i < realValue.Len() && !match; i++ {
					elemValue := realValue.Index(i)
					if _, ok := elemValue.Interface().(string); !ok {
						continue
					}
					// Check for a match with the regex pattern
					if pattern.MatchString(elemValue.Interface().(string)) {
						match = true
					}
				}
			}

			if realValue.Kind() != reflect.String {
				continue
			}

			if pattern.MatchString(realValue.Interface().(string)) {
				match = true
			}
		}
	}
	return match, nil
}

// matchUserBoolean matches a boolean based on user-provided conditions.
// dns.flags.qr: true
func matchUserBoolean(realValue, expectedValue reflect.Value) (bool, error) {
	// If realValue is a slice
	if realValue.Kind() == reflect.Slice {
		for i := 0; i < realValue.Len(); i++ {
			elemValue := realValue.Index(i)

			// Check if the element is a int
			if _, ok := elemValue.Interface().(bool); !ok {
				continue
			}

			// Check for match
			if expectedValue.Interface().(bool) == elemValue.Interface().(bool) {
				return true, nil
			}
		}
	}

	if realValue.Kind() != reflect.Bool {
		return false, nil
	}

	if expectedValue.Interface().(bool) != realValue.Interface().(bool) {
		return false, nil
	}
	return true, nil
}

// matchUserInteger matches an integer based on user-provided conditions.
// dns.opcode: 0
func matchUserInteger(realValue, expectedValue reflect.Value) (bool, error) {
	// If realValue is a slice
	if realValue.Kind() == reflect.Slice {
		for i := 0; i < realValue.Len(); i++ {
			elemValue := realValue.Index(i)

			// Check if the element is a int
			if _, ok := elemValue.Interface().(int); !ok {
				continue
			}

			// Check for match
			if expectedValue.Interface().(int) == elemValue.Interface().(int) {
				return true, nil
			}
		}
	}

	if realValue.Kind() != reflect.Int {
		return false, nil
	}
	if expectedValue.Interface().(int) != realValue.Interface().(int) {
		return false, nil
	}

	return true, nil
}

// matchUserPattern matches a pattern based on user-provided conditions.
// dns.qname: "^.*\\.github\\.com$"
func matchUserPattern(realValue, expectedValue reflect.Value) (bool, error) {
	pattern := regexp.MustCompile(expectedValue.Interface().(string))

	// If realValue is a slice
	if realValue.Kind() == reflect.Slice {
		for i := 0; i < realValue.Len(); i++ {
			elemValue := realValue.Index(i)

			// Check if the element is a string
			if _, ok := elemValue.Interface().(string); !ok {
				continue
			}

			// Check for a match with the regex pattern
			if pattern.MatchString(elemValue.Interface().(string)) {
				return true, nil
			}
		}
		// No match found in the slice
		return false, nil
	}

	// If realValue is not a string
	if realValue.Kind() != reflect.String {
		return false, nil
	}

	// Check for a match with the regex pattern
	if !pattern.MatchString(realValue.String()) {
		return false, nil
	}

	// Match found for a single value
	return true, nil
}

// getFieldByJSONTag retrieves a field value from a struct based on JSON tags.
func getFieldByJSONTag(value reflect.Value, nestedKeys string) (reflect.Value, bool) {
	listKeys := strings.SplitN(nestedKeys, ".", 2)
	jsonKey := listKeys[0]
	var remainingKeys string
	if len(listKeys) > 1 {
		remainingKeys = listKeys[1]
	}

	for i := 0; i < value.NumField(); i++ {
		field := value.Type().Field(i)

		// Get JSON tag
		tag := field.Tag.Get("json")
		tagClean := strings.TrimSuffix(tag, ",omitempty")

		// Check if the JSON tag matches
		if tagClean == jsonKey {
			fieldValue := value.Field(i)

			// Handle pointers safely
			if fieldValue.Kind() == reflect.Ptr {
				if fieldValue.IsNil() {
					return reflect.Value{}, false
				}
				fieldValue = fieldValue.Elem()
			}

			if remainingKeys == "" {
				// Base case: return the field value if no more keys are left
				return fieldValue, true
			}

			// Recurse into structs or handle slices
			switch fieldValue.Kind() {
			case reflect.Struct:
				return getFieldByJSONTag(fieldValue, remainingKeys)
			case reflect.Slice:
				if sliceElem, leftKey, found := getSliceElement(fieldValue, remainingKeys); found {
					// Handle the slice element based on its kind
					switch sliceElem.Kind() {
					case reflect.Struct:
						return getFieldByJSONTag(sliceElem, leftKey)
					case reflect.Slice, reflect.Array:
						var result []interface{}
						for i := 0; i < sliceElem.Len(); i++ {
							if subElem := sliceElem.Index(i); subElem.Kind() == reflect.Struct {
								if nestedValue, found := getFieldByJSONTag(subElem, leftKey); found {
									result = append(result, nestedValue.Interface())
								}
							} else {
								result = append(result, subElem.Interface())
							}
						}
						if len(result) > 0 {
							return reflect.ValueOf(result), true
						}
					default:
						return sliceElem, true
					}
				}
			default:
				return fieldValue, true
			}
		}
	}

	return reflect.Value{}, false
}

// getSliceElement retrieves an element from a slice based on the provided keys.
func getSliceElement(sliceValue reflect.Value, nestedKeys string) (reflect.Value, string, bool) {
	listKeys := strings.SplitN(nestedKeys, ".", 2)
	leftKeys := ""
	if len(listKeys) > 1 {
		leftKeys = listKeys[1]
	}
	sliceIndex := listKeys[0]

	if sliceIndex == "*" {
		return sliceValue, leftKeys, true
	}

	// Convert the slice index from string to int
	index, err := strconv.Atoi(sliceIndex)
	if err != nil || index < 0 || index >= sliceValue.Len() {
		// Handle the error (e.g., invalid index format or out of range)
		return reflect.Value{}, leftKeys, false
	}

	return sliceValue.Index(index), leftKeys, true
}
