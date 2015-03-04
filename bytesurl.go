// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package url parses URLs and implements query escaping.
// See RFC 3986.

package bytesurl

import (
	"bytes"
	"errors"
	"strconv"
)

// Errors - expressed as variables
var (
	ErrProtocolScheme    = errors.New("missing protocol scheme")
	ErrEmptyURL          = errors.New("empty url")
	ErrInvalidRequestURI = errors.New("invalid URI for request")
	ErrHexadeciamlEscape = errors.New("hexadecimal escape in host")
)

// Constants for URL
var (
	EmptyByte        = []byte("")
	SlashByte        = []byte("/")
	DoubleSlash      = []byte("//")
	TripleSlash      = []byte("///")
	FragmentByte     = []byte("#")
	QuestionMarkByte = []byte("?")
	AsteriskByte     = []byte("*")
	PercentByte      = []byte("%")
	EtaByte          = []byte("@")
	ColonByte        = []byte(":")
	EqualByte        = []byte("=")
	DotByte          = []byte(".")
	DoubleDotByte    = []byte("..")
)

// Error reports an error and the operation and URL that caused it.
type Error struct {
	Op  string
	URL string
	Err error
}

func (e *Error) Error() string { return e.Op + " " + e.URL + ": " + e.Err.Error() }

func ishex(c byte) bool {
	switch {
	case '0' <= c && c <= '9':
		return true
	case 'a' <= c && c <= 'f':
		return true
	case 'A' <= c && c <= 'F':
		return true
	}
	return false
}

func unhex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

type encoding int

const (
	encodePath encoding = 1 + iota
	encodeUserPassword
	encodeQueryComponent
	encodeFragment
)

// EscapeError -
type EscapeError string

func (e EscapeError) Error() string {
	return "invalid URL escape " + strconv.Quote(string(e))
}

// Return true if the specified character should be escaped when
// appearing in a URL string, according to RFC 3986.
func shouldEscape(c byte, mode encoding) bool {
	// §2.3 Unreserved characters (alphanum)
	if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' {
		return false
	}

	switch c {
	case '-', '_', '.', '~': // §2.3 Unreserved characters (mark)
		return false

	case '$', '&', '+', ',', '/', ':', ';', '=', '?', '@': // §2.2 Reserved characters (reserved)
		// Different sections of the URL allow a few of
		// the reserved characters to appear unescaped.
		switch mode {
		case encodePath: // §3.3
			// The RFC allows : @ & = + $ but saves / ; , for assigning
			// meaning to individual path segments. This package
			// only manipulates the path as a whole, so we allow those
			// last two as well. That leaves only ? to escape.
			return c == '?'

		case encodeUserPassword: // §3.2.1
			// The RFC allows ';', ':', '&', '=', '+', '$', and ',' in
			// userinfo, so we must escape only '@', '/', and '?'.
			// The parsing of userinfo treats ':' as special so we must escape
			// that too.
			return c == '@' || c == '/' || c == '?' || c == ':'

		case encodeQueryComponent: // §3.4
			// The RFC reserves (so we must escape) everything.
			return true

		case encodeFragment: // §4.1
			// The RFC text is silent but the grammar allows
			// everything, so escape nothing.
			return false
		}
	}

	// Everything else must be escaped.
	return true
}

// QueryUnescape does the inverse transformation of QueryEscape, converting
// %AB into the byte 0xAB and '+' into ' ' (space). It returns an error if
// any % is not followed by two hexadecimal digits.
func QueryUnescape(s []byte) ([]byte, error) {
	return unescape(s, encodeQueryComponent)
}

// unescape unescapes a string; the mode specifies
// which section of the URL string is being unescaped.
func unescape(s []byte, mode encoding) ([]byte, error) {
	// Count %, check that they're well-formed.
	n := 0
	hasPlus := false
	for i := 0; i < len(s); {
		switch s[i] {
		case '%':
			n++
			if i+2 >= len(s) || !ishex(s[i+1]) || !ishex(s[i+2]) {
				s = s[i:]
				if len(s) > 3 {
					s = s[0:3]
				}
				return EmptyByte, EscapeError(s)
			}
			i += 3
		case '+':
			hasPlus = mode == encodeQueryComponent
			i++
		default:
			i++
		}
	}

	if n == 0 && !hasPlus {
		return s, nil
	}

	t := make([]byte, len(s)-2*n)
	j := 0
	for i := 0; i < len(s); {
		switch s[i] {
		case '%':
			t[j] = unhex(s[i+1])<<4 | unhex(s[i+2])
			j++
			i += 3
		case '+':
			if mode == encodeQueryComponent {
				t[j] = ' '
			} else {
				t[j] = '+'
			}
			j++
			i++
		default:
			t[j] = s[i]
			j++
			i++
		}
	}
	return t, nil
}

// QueryEscape escapes the string so it can be safely placed
// inside a URL query.
func QueryEscape(b []byte) []byte {
	return escape(b, encodeQueryComponent)
}

func escape(s []byte, mode encoding) []byte {
	spaceCount, hexCount := 0, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if shouldEscape(c, mode) {
			if c == ' ' && mode == encodeQueryComponent {
				spaceCount++
			} else {
				hexCount++
			}
		}
	}

	if spaceCount == 0 && hexCount == 0 {
		return s
	}

	t := make([]byte, len(s)+2*hexCount)
	j := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == ' ' && mode == encodeQueryComponent:
			t[j] = '+'
			j++
		case shouldEscape(c, mode):
			t[j] = '%'
			t[j+1] = "0123456789ABCDEF"[c>>4]
			t[j+2] = "0123456789ABCDEF"[c&15]
			j += 3
		default:
			t[j] = s[i]
			j++
		}
	}
	return t
}

// A URL represents a parsed URL (technically, a URI reference).
// The general form represented is:
//
//	scheme://[userinfo@]host/path[?query][#fragment]
//
// URLs that do not start with a slash after the scheme are interpreted as:
//
//	scheme:opaque[?query][#fragment]
//
// Note that the Path field is stored in decoded form: /%47%6f%2f becomes /Go/.
// A consequence is that it is impossible to tell which slashes in the Path were
// slashes in the raw URL and which were %2f. This distinction is rarely important,
// but when it is a client must use other routines to parse the raw URL or construct
// the parsed URL. For example, an HTTP server can consult req.RequestURI, and
// an HTTP client can use URL{Host: "example.com", Opaque: "//example.com/Go%2f"}
// instead of URL{Host: "example.com", Path: "/Go/"}.
type URL struct {
	Scheme   []byte
	Opaque   []byte    // encoded opaque data
	User     *Userinfo // username and password information
	Host     []byte    // host or host:port
	Path     []byte
	RawQuery []byte // encoded query values, without '?'
	Fragment []byte // fragment for references, without '#'
}

// Maybe rawurl is of the form scheme:path.
// (Scheme must be [a-zA-Z][a-zA-Z0-9+-.]*)
// If so, return scheme, path; else return "", rawurl.
func getscheme(rawurl []byte) (scheme, path []byte, err error) {
	for i := 0; i < len(rawurl); i++ {
		c := rawurl[i]
		switch {
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z':
		// do nothing
		case '0' <= c && c <= '9' || c == '+' || c == '-' || c == '.':
			if i == 0 {
				return EmptyByte, rawurl, nil
			}
		case c == ':':
			if i == 0 {
				return EmptyByte, EmptyByte, ErrProtocolScheme
			}
			return rawurl[0:i], rawurl[i+1:], nil
		default:
			// we have encountered an invalid character,
			// so there is no valid scheme
			return EmptyByte, rawurl, nil
		}
	}
	return EmptyByte, rawurl, nil
}

// Maybe s is of the form t c u.
// If so, return t, c u (or t, u if cutc == true).
// If not, return s, "".
func split(s, c []byte, cutc bool) ([]byte, []byte) {
	i := bytes.Index(s, c)
	if i < 0 {
		return s, EmptyByte
	}
	if cutc {
		return s[0:i], s[i+len(c):]
	}
	return s[0:i], s[i:]
}

// Parse parses rawurl into a URL structure.
// The rawurl may be relative or absolute.
func Parse(rawurl []byte) (url *URL, err error) {
	// Cut off #frag
	u, frag := split(rawurl, FragmentByte, true)
	if url, err = parse(u, false); err != nil {
		return nil, err
	}
	if bytes.Equal(frag, EmptyByte) {
		return url, nil
	}
	if url.Fragment, err = unescape(frag, encodeFragment); err != nil {
		return nil, &Error{"parse", string(rawurl), err}
	}
	return url, nil
}

// ParseRequestURI parses rawurl into a URL structure.  It assumes that
// rawurl was received in an HTTP request, so the rawurl is interpreted
// only as an absolute URI or an absolute path.
// The string rawurl is assumed not to have a #fragment suffix.
// (Web browsers strip #fragment before sending the URL to a web server.)
func ParseRequestURI(rawurl []byte) (url *URL, err error) {
	return parse(rawurl, true)
}

// parse parses a URL from a string in one of two contexts.  If
// viaRequest is true, the URL is assumed to have arrived via an HTTP request,
// in which case only absolute URLs or path-absolute relative URLs are allowed.
// If viaRequest is false, all forms of relative URLs are allowed.
func parse(rawurl []byte, viaRequest bool) (url *URL, err error) {
	var rest []byte

	if bytes.Equal(rawurl, EmptyByte) && viaRequest {
		err = ErrEmptyURL
		goto Error
	}
	url = new(URL)

	if bytes.Equal(rawurl, AsteriskByte) {
		url.Path = AsteriskByte
		return
	}

	// Split off possible leading "http:", "mailto:", etc.
	// Cannot contain escaped characters.
	if url.Scheme, rest, err = getscheme(rawurl); err != nil {
		goto Error
	}
	url.Scheme = bytes.ToLower(url.Scheme)

	rest, url.RawQuery = split(rest, QuestionMarkByte, true)

	if !bytes.HasPrefix(rest, SlashByte) {
		if bytes.Compare(url.Scheme, EmptyByte) != 0 {
			// We consider rootless paths per RFC 3986 as opaque.
			url.Opaque = rest
			return url, nil
		}
		if viaRequest {
			err = ErrInvalidRequestURI
			goto Error
		}
	}

	if (bytes.Compare(url.Scheme, EmptyByte) != 0 || !viaRequest && !bytes.HasPrefix(rest, TripleSlash)) && bytes.HasPrefix(rest, DoubleSlash) {
		var authority []byte
		authority, rest = split(rest[2:], SlashByte, false)
		url.User, url.Host, err = parseAuthority(authority)
		if err != nil {
			goto Error
		}
		if bytes.Contains(url.Host, PercentByte) {
			err = ErrHexadeciamlEscape
			goto Error
		}
	}
	if url.Path, err = unescape(rest, encodePath); err != nil {
		goto Error
	}
	return url, nil

Error:
	return nil, &Error{"parse", string(rawurl), err}
}

func parseAuthority(authority []byte) (user *Userinfo, host []byte, err error) {
	i := bytes.LastIndex(authority, EtaByte)
	if i < 0 {
		host = authority
		return
	}
	userinfo, host := authority[:i], authority[i+1:]
	if bytes.Index(userinfo, ColonByte) < 0 {
		if userinfo, err = unescape(userinfo, encodeUserPassword); err != nil {
			return
		}
		user = User(userinfo)
	} else {
		username, password := split(userinfo, ColonByte, true)
		if username, err = unescape(username, encodeUserPassword); err != nil {
			return
		}
		if password, err = unescape(password, encodeUserPassword); err != nil {
			return
		}
		user = UserPassword(username, password)
	}
	return
}

// Bytes reassembles the URL into a valid URL string.
// The general form of the result is one of:
//
//	scheme:opaque
//	scheme://userinfo@host/path?query#fragment
//
// If u.Opaque is non-empty, String uses the first form;
// otherwise it uses the second form.
//
// In the second form, the following rules apply:
//	- if u.Scheme is empty, scheme: is omitted.
//	- if u.User is nil, userinfo@ is omitted.
//	- if u.Host is empty, host/ is omitted.
//	- if u.Scheme and u.Host are empty and u.User is nil,
//	   the entire scheme://userinfo@host/ is omitted.
//	- if u.Host is non-empty and u.Path begins with a /,
//	   the form host/path does not add its own /.
//	- if u.RawQuery is empty, ?query is omitted.
//	- if u.Fragment is empty, #fragment is omitted.
func (u *URL) String() string {
	return string(u.Bytes())
}

// Bytes -
func (u *URL) Bytes() []byte {
	var buf bytes.Buffer
	if bytes.Compare(u.Scheme, EmptyByte) != 0 {
		buf.Write(u.Scheme)
		buf.WriteByte(':')
	}
	if bytes.Compare(u.Opaque, EmptyByte) != 0 {
		buf.Write(u.Opaque)
	} else {
		if bytes.Compare(u.Scheme, EmptyByte) != 0 || bytes.Compare(u.Host, EmptyByte) != 0 || u.User != nil {
			buf.Write(DoubleSlash)
			if ui := u.User; ui != nil {
				buf.Write(ui.Bytes())
				buf.WriteByte('@')
			}
			if h := u.Host; bytes.Compare(h, EmptyByte) != 0 {
				buf.Write(h)
			}
		}
		if bytes.Compare(u.Path, EmptyByte) != 0 && u.Path[0] != '/' && bytes.Compare(u.Host, EmptyByte) != 0 {
			buf.WriteByte('/')
		}
		buf.Write(escape(u.Path, encodePath))
	}
	if bytes.Compare(u.RawQuery, EmptyByte) != 0 {
		buf.WriteByte('?')
		buf.Write(u.RawQuery)
	}
	if bytes.Compare(u.Fragment, EmptyByte) != 0 {
		buf.WriteByte('#')
		buf.Write(escape(u.Fragment, encodeFragment))
	}
	return buf.Bytes()
}

// resolvePath applies special path segments from refs and applies
// them to base, per RFC 3986.
func resolvePath(base, ref []byte) []byte {
	var buffer bytes.Buffer
	if bytes.Equal(ref, EmptyByte) {
		buffer.Write(base)
	} else if ref[0] != '/' {
		i := bytes.LastIndex(base, SlashByte)
		buffer.Write(base[:i+1])
		buffer.Write(ref)
	} else {
		buffer.Write(ref)
	}
	if buffer.Len() == 0 {
		return EmptyByte
	}
	var dst [][]byte
	src := bytes.Split(buffer.Bytes(), SlashByte)
	for _, elem := range src {
		if bytes.Equal(elem, DotByte) {
			// drop
		} else if bytes.Equal(elem, DoubleDotByte) {
			if len(dst) > 0 {
				dst = dst[:len(dst)-1]
			}
		} else {
			dst = append(dst, elem)
		}
	}
	if last := src[len(src)-1]; bytes.Equal(last, DotByte) || bytes.Equal(last, DoubleDotByte) {
		// Add final slash to the joined path.
		dst = append(dst, EmptyByte)
	}
	return append(SlashByte, bytes.TrimLeft(bytes.Join(dst, SlashByte), "/")...)
}

// IsAbs returns true if the URL is absolute.
func (u *URL) IsAbs() bool {
	return bytes.Compare(u.Scheme, EmptyByte) != 0
}

// Parse parses a URL in the context of the receiver.  The provided URL
// may be relative or absolute.  Parse returns nil, err on parse
// failure, otherwise its return value is the same as ResolveReference.
func (u *URL) Parse(ref []byte) (*URL, error) {
	refurl, err := Parse(ref)
	if err != nil {
		return nil, err
	}
	return u.ResolveReference(refurl), nil
}

// ResolveReference resolves a URI reference to an absolute URI from
// an absolute base URI, per RFC 3986 Section 5.2.  The URI reference
// may be relative or absolute.  ResolveReference always returns a new
// URL instance, even if the returned URL is identical to either the
// base or reference. If ref is an absolute URL, then ResolveReference
// ignores base and returns a copy of ref.
func (u *URL) ResolveReference(ref *URL) *URL {
	url := *ref
	if bytes.Equal(ref.Scheme, EmptyByte) {
		url.Scheme = u.Scheme
	}
	if bytes.Compare(ref.Scheme, EmptyByte) != 0 || bytes.Compare(ref.Host, EmptyByte) != 0 || ref.User != nil {
		// The "absoluteURI" or "net_path" cases.
		url.Path = resolvePath(ref.Path, EmptyByte)
		return &url
	}
	if bytes.Compare(ref.Opaque, EmptyByte) != 0 {
		url.User = nil
		url.Host = EmptyByte
		url.Path = EmptyByte
		return &url
	}
	if bytes.Equal(ref.Path, EmptyByte) {
		if bytes.Equal(ref.RawQuery, EmptyByte) {
			url.RawQuery = u.RawQuery
			if bytes.Equal(ref.Fragment, EmptyByte) {
				url.Fragment = u.Fragment
			}
		}
	}
	// The "abs_path" or "rel_path" cases.
	url.Host = u.Host
	url.User = u.User
	url.Path = resolvePath(u.Path, ref.Path)
	return &url
}

// Query parses RawQuery and returns the corresponding values.
func (u *URL) Query() Values {
	v, _ := ParseQuery(u.RawQuery)
	return v
}

// RequestURI returns the encoded path?query or opaque?query
// string that would be used in an HTTP request for u.
func (u *URL) RequestURI() (result []byte) {
	var buffer bytes.Buffer
	result = u.Opaque
	if bytes.Equal(result, EmptyByte) {
		result = escape(u.Path, encodePath)
		if bytes.Equal(result, EmptyByte) {
			result = SlashByte
		}
	} else {
		if bytes.HasPrefix(result, DoubleSlash) {
			result = append(append(u.Scheme, ColonByte...), result...)
		}
	}
	buffer.Write(result)
	if bytes.Compare(u.RawQuery, EmptyByte) != 0 {
		buffer.Write(QuestionMarkByte)
		buffer.Write(u.RawQuery)
	}
	return buffer.Bytes()
}
