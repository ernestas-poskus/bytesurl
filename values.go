package bytesurl

import (
	"bytes"
	"sort"
)

// Values maps a string key to a list of values.
// It is typically used for query parameters and form values.
// Unlike in the http.Header map, the keys in a Values map
// are case-sensitive.
type Values map[string][][]byte

// Get gets the first value associated with the given key.
// If there are no values associated with the key, Get returns
// the empty string. To access multiple values, use the map
// directly.
func (v Values) Get(key string) []byte {
	if v == nil {
		return EmptyByte
	}
	vs, ok := v[key]
	if !ok || len(vs) == 0 {
		return EmptyByte
	}
	return vs[0]
}

// Set sets the key to value. It replaces any existing
// values.
func (v Values) Set(key string, value []byte) {
	v[key] = [][]byte{value}
}

// Add adds the value to key. It appends to any existing
// values associated with key.
func (v Values) Add(key string, value []byte) {
	v[key] = append(v[key], value)
}

// Del deletes the values associated with key.
func (v Values) Del(key string) {
	delete(v, key)
}

// ParseQuery parses the URL-encoded query string and returns
// a map listing the values specified for each key.
// ParseQuery always returns a non-nil map containing all the
// valid query parameters found; err describes the first decoding error
// encountered, if any.
func ParseQuery(query []byte) (m Values, err error) {
	m = make(Values)
	err = parseQuery(m, query)
	return
}

func parseQuery(m Values, query []byte) (err error) {
	for bytes.Compare(query, EmptyByte) != 0 {
		key := query
		if i := bytes.IndexAny(key, "&;"); i >= 0 {
			key, query = key[:i], key[i+1:]
		} else {
			query = EmptyByte
		}
		if bytes.Equal(key, EmptyByte) {
			continue
		}
		value := EmptyByte
		if i := bytes.Index(key, EqualByte); i >= 0 {
			key, value = key[:i], key[i+1:]
		}
		key, err1 := QueryUnescape(key)
		if err1 != nil {
			if err == nil {
				err = err1
			}
			continue
		}
		value, err1 = QueryUnescape(value)
		if err1 != nil {
			if err == nil {
				err = err1
			}
			continue
		}
		indexKey := string(key)
		m[indexKey] = append(m[indexKey], value)
	}
	return err
}

// Encode encodes the values into ``URL encoded'' form
// ("bar=baz&foo=quux") sorted by key.
func (v Values) Encode() string {
	if v == nil {
		return ""
	}
	var buf bytes.Buffer
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		vs := v[k]
		prefix := append(QueryEscape([]byte(k)), EqualByte...)
		for _, v := range vs {
			if buf.Len() > 0 {
				buf.WriteByte('&')
			}
			buf.Write(prefix)
			buf.Write(QueryEscape(v))
		}
	}
	return buf.String()
}
