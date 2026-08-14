// Package plist provides a minimal, dependency-free decoder for Apple property
// lists.
//
// It exists because the things this tool needs to read -- entitlement blobs
// emitted by codesign(1) and launchd job descriptions -- are property lists,
// and the previous approach of matching substrings against the raw text was
// wrong in both directions. codesign emits its XML on a single line, so a
// line-oriented parser sees nothing at all; and a substring match cannot tell
// `<key>com.apple.security.app-sandbox</key><true/>` from the same key set to
// `<false/>`.
//
// Only the subset of the format that appears in entitlements and launchd
// plists is supported: dict, array, string, integer, real, true, false, data,
// and date. Binary property lists are converted to XML via plutil(1) before
// decoding.
package plist

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Dict is a decoded property list dictionary. Values are one of: Dict,
// []interface{}, string, bool, int64, float64, or []byte.
type Dict map[string]interface{}

// String returns the string value at key, or "" if absent or not a string.
func (d Dict) String(key string) string {
	s, _ := d[key].(string)
	return s
}

// Bool reports the boolean value at key. Integers are treated as booleans so
// that `<integer>1</integer>` behaves like `<true/>`, which launchd accepts.
func (d Dict) Bool(key string) bool {
	switch v := d[key].(type) {
	case bool:
		return v
	case int64:
		return v != 0
	}
	return false
}

// StringSlice returns the array at key as strings, skipping non-string
// elements. A bare string value is returned as a single-element slice.
func (d Dict) StringSlice(key string) []string {
	switch v := d[key].(type) {
	case string:
		return []string{v}
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// Keys returns the dictionary's keys in unspecified order.
func (d Dict) Keys() []string {
	keys := make([]string, 0, len(d))
	for k := range d {
		keys = append(keys, k)
	}
	return keys
}

// ParseFile reads and decodes the property list at path.
func ParseFile(path string) (Dict, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse decodes a property list, which may be XML or binary, and may be
// preceded by an embedded-entitlement blob header of the kind older versions
// of codesign(1) emit.
func Parse(data []byte) (Dict, error) {
	xmlData, err := normalize(data)
	if err != nil {
		return nil, err
	}

	root, err := parseXML(xmlData)
	if err != nil {
		return nil, err
	}

	dict, ok := root.(Dict)
	if !ok {
		return nil, fmt.Errorf("plist root is %T, want dict", root)
	}
	return dict, nil
}

// normalize converts arbitrary property list bytes into XML.
//
// codesign's `--entitlements -` output is not always a bare plist: before
// macOS 12 it is wrapped in a CS_GenericBlob header (magic 0xfade7171 followed
// by a big-endian length), and it may be a binary plist. Both are handled here
// so callers see plain XML.
func normalize(data []byte) ([]byte, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, io.ErrUnexpectedEOF
	}

	// Strip an embedded entitlement blob wrapper, if present.
	if len(data) > 8 && data[0] == 0xfa && data[1] == 0xde {
		data = data[8:]
	}

	// A binary plist has to go through plutil; we do not decode bplist here.
	if bytes.HasPrefix(data, []byte("bplist00")) {
		return toXMLViaPlutil(data)
	}

	// Otherwise trim any leading noise ahead of the XML declaration or root.
	if !bytes.HasPrefix(data, []byte("<?xml")) && !bytes.HasPrefix(data, []byte("<plist")) {
		if i := bytes.Index(data, []byte("<?xml")); i >= 0 {
			data = data[i:]
		} else if i := bytes.Index(data, []byte("<plist")); i >= 0 {
			data = data[i:]
		}
	}

	return data, nil
}

func toXMLViaPlutil(data []byte) ([]byte, error) {
	cmd := exec.Command("plutil", "-convert", "xml1", "-o", "-", "-")
	cmd.Stdin = bytes.NewReader(data)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("plutil could not convert binary plist: %w", err)
	}
	return out, nil
}

func parseXML(data []byte) (interface{}, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	// Apple's plists reference an external DTD that we neither have nor want
	// to fetch; non-strict mode keeps the decoder from caring.
	dec.Strict = false

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil, fmt.Errorf("no plist element found")
		}
		if err != nil {
			return nil, err
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch start.Name.Local {
		case "plist":
			return nextValue(dec)
		case "dict", "array":
			// Tolerate a plist body with no <plist> wrapper.
			return parseValue(dec, start)
		}
	}
}

// nextValue advances to the next start element and decodes it.
func nextValue(dec *xml.Decoder) (interface{}, error) {
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			return parseValue(dec, t)
		case xml.EndElement:
			return nil, fmt.Errorf("unexpected </%s>", t.Name.Local)
		}
	}
}

func parseValue(dec *xml.Decoder, start xml.StartElement) (interface{}, error) {
	switch start.Name.Local {
	case "dict":
		return parseDict(dec)
	case "array":
		return parseArray(dec)
	case "true":
		return true, dec.Skip()
	case "false":
		return false, dec.Skip()
	case "string", "date":
		return charData(dec, start)
	case "integer":
		s, err := charData(dec, start)
		if err != nil {
			return nil, err
		}
		n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		if err != nil {
			return nil, nil // malformed integer: record as absent, not fatal
		}
		return n, nil
	case "real":
		s, err := charData(dec, start)
		if err != nil {
			return nil, err
		}
		f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
		if err != nil {
			return nil, nil
		}
		return f, nil
	case "data":
		s, err := charData(dec, start)
		if err != nil {
			return nil, err
		}
		raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
		if err != nil {
			return nil, nil
		}
		return raw, nil
	default:
		// Unknown element: consume it so decoding can continue.
		return nil, dec.Skip()
	}
}

func parseDict(dec *xml.Decoder) (Dict, error) {
	dict := Dict{}
	var key string
	haveKey := false

	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "key" {
				k, err := charData(dec, t)
				if err != nil {
					return nil, err
				}
				key, haveKey = k, true
				continue
			}
			val, err := parseValue(dec, t)
			if err != nil {
				return nil, err
			}
			// A value with no preceding <key> is malformed; drop it rather
			// than misattributing it to the previous key.
			if haveKey {
				dict[key] = val
				haveKey = false
			}
		case xml.EndElement:
			if t.Name.Local == "dict" {
				return dict, nil
			}
		}
	}
}

func parseArray(dec *xml.Decoder) ([]interface{}, error) {
	arr := make([]interface{}, 0)
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			val, err := parseValue(dec, t)
			if err != nil {
				return nil, err
			}
			arr = append(arr, val)
		case xml.EndElement:
			if t.Name.Local == "array" {
				return arr, nil
			}
		}
	}
}

// charData returns the text content of the element that start opened,
// consuming through its end tag.
func charData(dec *xml.Decoder, start xml.StartElement) (string, error) {
	var sb strings.Builder
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", err
		}
		switch t := tok.(type) {
		case xml.CharData:
			if depth == 0 {
				sb.Write(t)
			}
		case xml.StartElement:
			depth++
		case xml.EndElement:
			if depth == 0 && t.Name.Local == start.Name.Local {
				return sb.String(), nil
			}
			depth--
		}
	}
}

// Describe renders a decoded plist value as a compact single-line string, for
// display in reports.
func Describe(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return ""
	case bool:
		return strconv.FormatBool(t)
	case string:
		return t
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'g', -1, 64)
	case []byte:
		return fmt.Sprintf("<%d bytes>", len(t))
	case []interface{}:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			parts = append(parts, Describe(e))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case Dict:
		parts := make([]string, 0, len(t))
		for _, k := range t.Keys() {
			parts = append(parts, k+"="+Describe(t[k]))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	default:
		return fmt.Sprintf("%v", t)
	}
}
