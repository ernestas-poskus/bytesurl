// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bytesurl

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type URLTest struct {
	in        []byte
	out       *URL
	roundtrip []byte // expected result of reserializing the URL; empty means same as "in".
}

var urltests = []URLTest{
	// no path
	{
		[]byte("http://www.google.com"),
		&URL{
			Scheme: []byte("http"),
			Host:   []byte("www.google.com"),
		},
		[]byte(""),
	},
	// path
	{
		[]byte("http://www.google.com/"),
		&URL{
			Scheme: []byte("http"),
			Host:   []byte("www.google.com"),
			Path:   []byte("/"),
		},
		[]byte(""),
	},
	// path with hex escaping
	{
		[]byte("http://www.google.com/file%20one%26two"),
		&URL{
			Scheme: []byte("http"),
			Host:   []byte("www.google.com"),
			Path:   []byte("/file one&two"),
		},
		[]byte("http://www.google.com/file%20one&two"),
	},
	// user
	{
		[]byte("ftp://webmaster@www.google.com/"),
		&URL{
			Scheme: []byte("ftp"),
			User:   User([]byte("webmaster")),
			Host:   []byte("www.google.com"),
			Path:   []byte("/"),
		},
		[]byte(""),
	},
	// escape sequence in username
	{
		[]byte("ftp://john%20doe@www.google.com/"),
		&URL{
			Scheme: []byte("ftp"),
			User:   User([]byte("john doe")),
			Host:   []byte("www.google.com"),
			Path:   []byte("/"),
		},
		[]byte("ftp://john%20doe@www.google.com/"),
	},
	// query
	{
		[]byte("http://www.google.com/?q=go+language"),
		&URL{
			Scheme:   []byte("http"),
			Host:     []byte("www.google.com"),
			Path:     []byte("/"),
			RawQuery: []byte("q=go+language"),
		},
		[]byte(""),
	},
	// query with hex escaping: NOT parsed
	{
		[]byte("http://www.google.com/?q=go%20language"),
		&URL{
			Scheme:   []byte("http"),
			Host:     []byte("www.google.com"),
			Path:     []byte("/"),
			RawQuery: []byte("q=go%20language"),
		},
		[]byte(""),
	},
	// %20 outside query
	{
		[]byte("http://www.google.com/a%20b?q=c+d"),
		&URL{
			Scheme:   []byte("http"),
			Host:     []byte("www.google.com"),
			Path:     []byte("/a b"),
			RawQuery: []byte("q=c+d"),
		},
		[]byte(""),
	},
	// path without leading /, so no parsing
	{
		[]byte("http:www.google.com/?q=go+language"),
		&URL{
			Scheme:   []byte("http"),
			Opaque:   []byte("www.google.com/"),
			RawQuery: []byte("q=go+language"),
		},
		[]byte("http:www.google.com/?q=go+language"),
	},
	// path without leading /, so no parsing
	{
		[]byte("http:%2f%2fwww.google.com/?q=go+language"),
		&URL{
			Scheme:   []byte("http"),
			Opaque:   []byte("%2f%2fwww.google.com/"),
			RawQuery: []byte("q=go+language"),
		},
		[]byte("http:%2f%2fwww.google.com/?q=go+language"),
	},
	// non-authority with path
	{
		[]byte("mailto:/webmaster@golang.org"),
		&URL{
			Scheme: []byte("mailto"),
			Path:   []byte("/webmaster@golang.org"),
		},
		[]byte("mailto:///webmaster@golang.org"), // unfortunate compromise
	},
	// non-authority
	{
		[]byte("mailto:webmaster@golang.org"),
		&URL{
			Scheme: []byte("mailto"),
			Opaque: []byte("webmaster@golang.org"),
		},
		[]byte(""),
	},
	// unescaped :// in query should not create a scheme
	{
		[]byte("/foo?query=http://bad"),
		&URL{
			Path:     []byte("/foo"),
			RawQuery: []byte("query=http://bad"),
		},
		[]byte(""),
	},
	// leading // without scheme should create an authority
	{
		[]byte("//foo"),
		&URL{
			Host: []byte("foo"),
		},
		[]byte(""),
	},
	// leading // without scheme, with userinfo, path, and query
	{
		[]byte("//user@foo/path?a=b"),
		&URL{
			User:     User([]byte("user")),
			Host:     []byte("foo"),
			Path:     []byte("/path"),
			RawQuery: []byte("a=b"),
		},
		[]byte(""),
	},
	// Three leading slashes isn't an authority, but doesn't return an error.
	// (We can't return an error, as this code is also used via
	// ServeHTTP -> ReadRequest -> Parse, which is arguably a
	// different URL parsing context, but currently shares the
	// same codepath)
	{
		[]byte("///threeslashes"),
		&URL{
			Path: []byte("///threeslashes"),
		},
		[]byte(""),
	},
	{
		[]byte("http://user:password@google.com"),
		&URL{
			Scheme: []byte("http"),
			User:   UserPassword([]byte("user"), []byte("password")),
			Host:   []byte("google.com"),
		},
		[]byte("http://user:password@google.com"),
	},
	// unescaped @ in username should not confuse host
	{
		[]byte("http://j@ne:password@google.com"),
		&URL{
			Scheme: []byte("http"),
			User:   UserPassword([]byte("j@ne"), []byte("password")),
			Host:   []byte("google.com"),
		},
		[]byte("http://j%40ne:password@google.com"),
	},
	// unescaped @ in password should not confuse host
	{
		[]byte("http://jane:p@ssword@google.com"),
		&URL{
			Scheme: []byte("http"),
			User:   UserPassword([]byte("jane"), []byte("p@ssword")),
			Host:   []byte("google.com"),
		},
		[]byte("http://jane:p%40ssword@google.com"),
	},
	{
		[]byte("http://j@ne:password@google.com/p@th?q=@go"),
		&URL{
			Scheme:   []byte("http"),
			User:     UserPassword([]byte("j@ne"), []byte("password")),
			Host:     []byte("google.com"),
			Path:     []byte("/p@th"),
			RawQuery: []byte("q=@go"),
		},
		[]byte("http://j%40ne:password@google.com/p@th?q=@go"),
	},
	{
		[]byte("http://www.google.com/?q=go+language#foo"),
		&URL{
			Scheme:   []byte("http"),
			Host:     []byte("www.google.com"),
			Path:     []byte("/"),
			RawQuery: []byte("q=go+language"),
			Fragment: []byte("foo"),
		},
		[]byte(""),
	},
	{
		[]byte("http://www.google.com/?q=go+language#foo%26bar"),
		&URL{
			Scheme:   []byte("http"),
			Host:     []byte("www.google.com"),
			Path:     []byte("/"),
			RawQuery: []byte("q=go+language"),
			Fragment: []byte("foo&bar"),
		},
		[]byte("http://www.google.com/?q=go+language#foo&bar"),
	},
	{
		[]byte("file:///home/adg/rabbits"),
		&URL{
			Scheme: []byte("file"),
			Host:   []byte(""),
			Path:   []byte("/home/adg/rabbits"),
		},
		[]byte("file:///home/adg/rabbits"),
	},
	// "Windows" paths are no exception to the rule.
	// See golang.org/issue/6027, especially comment #9.
	{
		[]byte("file:///C:/FooBar/Baz.txt"),
		&URL{
			Scheme: []byte("file"),
			Host:   []byte(""),
			Path:   []byte("/C:/FooBar/Baz.txt"),
		},
		[]byte("file:///C:/FooBar/Baz.txt"),
	},
	// case-insensitive scheme
	{
		[]byte("MaIlTo:webmaster@golang.org"),
		&URL{
			Scheme: []byte("mailto"),
			Opaque: []byte("webmaster@golang.org"),
		},
		[]byte("mailto:webmaster@golang.org"),
	},
	// Relative path
	{
		[]byte("a/b/c"),
		&URL{
			Path: []byte("a/b/c"),
		},
		[]byte("a/b/c"),
	},
	// escaped '?' in username and password
	{
		[]byte("http://%3Fam:pa%3Fsword@google.com"),
		&URL{
			Scheme: []byte("http"),
			User:   UserPassword([]byte("?am"), []byte("pa?sword")),
			Host:   []byte("google.com"),
		},
		[]byte(""),
	},
}

// more useful string for debugging than fmt's struct printer
func ufmt(u *URL) string {
	var user, pass interface{}
	if u.User != nil {
		user = u.User.Username()
		if p, ok := u.User.Password(); ok {
			pass = p
		}
	}
	return fmt.Sprintf("opaque=%q, scheme=%q, user=%#v, pass=%#v, host=%q, path=%q, rawq=%q, frag=%q",
		u.Opaque, u.Scheme, user, pass, u.Host, u.Path, u.RawQuery, u.Fragment)
}

func DoTest(t *testing.T, parse func([]byte) (*URL, error), name string, tests []URLTest) {
	for _, tt := range tests {
		u, err := parse(tt.in)
		if err != nil {
			t.Errorf("%s(%q) returned error %s", name, tt.in, err)
			continue
		}
		// if !reflect.DeepEqual(u, tt.out) {
		if u.String() != tt.out.String() {
			t.Errorf("%s(%q):\n\thave %v\n\twant %v\n",
				name, tt.in, u.String(), tt.out.String())
		}
	}
}

func BenchmarkString(b *testing.B) {
	b.StopTimer()
	b.ReportAllocs()
	for _, tt := range urltests {
		u, err := Parse(tt.in)
		if err != nil {
			b.Errorf("Parse(%q) returned error %s", tt.in, err)
			continue
		}
		if bytes.Equal(tt.roundtrip, []byte("")) {
			continue
		}
		b.StartTimer()
		var g []byte
		for i := 0; i < b.N; i++ {
			g = u.Bytes()
		}
		b.StopTimer()
		if w := tt.roundtrip; bytes.Compare(g, w) != 0 {
			b.Errorf("Parse(%q).String() == %q, want %q", tt.in, g, w)
		}
	}
}

func BenchmarkBytes(b *testing.B) {
	b.StopTimer()
	b.ReportAllocs()
	for _, tt := range urltests {
		u, err := Parse(tt.in)
		if err != nil {
			b.Errorf("Parse(%q) returned error %s", tt.in, err)
			continue
		}
		if bytes.Equal(tt.roundtrip, []byte("")) {
			continue
		}
		b.StartTimer()
		var g []byte
		for i := 0; i < b.N; i++ {
			g = u.Bytes()
		}
		b.StopTimer()
		if w := tt.roundtrip; bytes.Compare(g, w) != 0 {
			b.Errorf("Parse(%q).String() == %q, want %q", tt.in, g, w)
		}
	}
}
func TestParse(t *testing.T) {
	DoTest(t, Parse, "Parse", urltests)
}

const pathThatLooksSchemeRelative = "//not.a.user@not.a.host/just/a/path"

var parseRequestURLTests = []struct {
	url           []byte
	expectedValid bool
}{
	{[]byte("http://foo.com"), true},
	{[]byte("http://foo.com/"), true},
	{[]byte("http://foo.com/path"), true},
	{[]byte("/"), true},
	{[]byte(pathThatLooksSchemeRelative), true},

	{[]byte("//not.a.user@%66%6f%6f.com/just/a/path/also"), true},
	{[]byte("foo.html"), false},
	{[]byte("../dir/"), false},
	{[]byte("*"), true},
}

func TestParseRequestURI(t *testing.T) {
	for _, test := range parseRequestURLTests {
		_, err := ParseRequestURI(test.url)
		valid := err == nil
		if valid != test.expectedValid {
			t.Errorf("Expected valid=%v for %q; got %v", test.expectedValid, test.url, valid)
		}
	}

	url, err := ParseRequestURI([]byte(pathThatLooksSchemeRelative))
	if err != nil {
		t.Fatalf("Unexpected error %v", err)
	}
	if string(url.Path) != pathThatLooksSchemeRelative {
		t.Errorf("Expected path %q; got %q", pathThatLooksSchemeRelative, url.Path)
	}
}

func DoTestString(t *testing.T, parse func([]byte) (*URL, error), name string, tests []URLTest) {
	for _, tt := range tests {
		u, err := parse(tt.in)
		if err != nil {
			t.Errorf("%s(%q) returned error %s", name, tt.in, err)
			continue
		}
		expected := tt.in
		if len(tt.roundtrip) > 0 {
			expected = tt.roundtrip
		}
		s := u.Bytes()
		if bytes.Compare(s, expected) != 0 {
			t.Errorf("%s(%q).String() == %q (expected %q)", name, tt.in, s, expected)
		}
	}
}

func TestURLString(t *testing.T) {
	DoTestString(t, Parse, "Parse", urltests)

	// no leading slash on path should prepend
	// slash on String() call
	noslash := URLTest{
		[]byte("http://www.google.com/search"),
		&URL{
			Scheme: []byte("http"),
			Host:   []byte("www.google.com"),
			Path:   []byte("search"),
		},
		[]byte(""),
	}
	s := noslash.out.Bytes()
	if bytes.Compare(s, noslash.in) != 0 {
		t.Errorf("Expected %s; go %s", noslash.in, s)
	}
}

type EscapeTest struct {
	in  []byte
	out []byte
	err error
}

var unescapeTests = []EscapeTest{
	{
		[]byte(""),
		[]byte(""),
		nil,
	},
	{
		[]byte("abc"),
		[]byte("abc"),
		nil,
	},
	{
		[]byte("1%41"),
		[]byte("1A"),
		nil,
	},
	{
		[]byte("1%41%42%43"),
		[]byte("1ABC"),
		nil,
	},
	{
		[]byte("%4a"),
		[]byte("J"),
		nil,
	},
	{
		[]byte("%6F"),
		[]byte("o"),
		nil,
	},
	{
		[]byte("%"), // not enough characters after %
		[]byte(""),
		EscapeError("%"),
	},
	{
		[]byte("%a"), // not enough characters after %
		[]byte(""),
		EscapeError("%a"),
	},
	{
		[]byte("%1"), // not enough characters after %
		[]byte(""),
		EscapeError("%1"),
	},
	{
		[]byte("123%45%6"), // not enough characters after %
		[]byte(""),
		EscapeError("%6"),
	},
	{
		[]byte("%zzzzz"), // invalid hex digits
		[]byte(""),
		EscapeError("%zz"),
	},
}

func TestUnescape(t *testing.T) {
	for _, tt := range unescapeTests {
		actual, err := QueryUnescape(tt.in)
		if bytes.Compare(actual, tt.out) != 0 || (err != nil) != (tt.err != nil) {
			t.Errorf("QueryUnescape(%q) = %q, %s; want %q, %s", tt.in, actual, err, tt.out, tt.err)
		}
	}
}

var escapeTests = []EscapeTest{
	{
		[]byte(""),
		[]byte(""),
		nil,
	},
	{
		[]byte("abc"),
		[]byte("abc"),
		nil,
	},
	{
		[]byte("one two"),
		[]byte("one+two"),
		nil,
	},
	{
		[]byte("10%"),
		[]byte("10%25"),
		nil,
	},
	{
		[]byte(" ?&=#+%!<>#\"{}|\\^[]`☺\t:/@$'()*,;"),
		[]byte("+%3F%26%3D%23%2B%25%21%3C%3E%23%22%7B%7D%7C%5C%5E%5B%5D%60%E2%98%BA%09%3A%2F%40%24%27%28%29%2A%2C%3B"),
		nil,
	},
}

func TestEscape(t *testing.T) {
	for _, tt := range escapeTests {
		actual := QueryEscape(tt.in)
		if bytes.Compare(tt.out, actual) != 0 {
			t.Errorf("QueryEscape(%q) = %q, want %q", tt.in, actual, tt.out)
		}

		// for bonus points, verify that escape:unescape is an identity.
		roundtrip, err := QueryUnescape(actual)
		if bytes.Compare(roundtrip, tt.in) != 0 || err != nil {
			t.Errorf("QueryUnescape(%q) = %q, %s; want %q, %s", actual, roundtrip, err, tt.in, "[no error]")
		}
	}
}

//var userinfoTests = []UserinfoTest{
//	{[]byte("user"), []byte("password"), []byte("user:password")},
//	{[]byte("foo:bar"), []byte("~!@#$%^&*()_+{}|[]\\-=`:;'\"<>?,./",
//		"foo%3Abar:~!%40%23$%25%5E&*()_+%7B%7D%7C%5B%5D%5C-=%60%3A;'%22%3C%3E?,.%2F")},
//}

type EncodeQueryTest struct {
	m        Values
	expected string
}

var encodeQueryTests = []EncodeQueryTest{
	{nil, ""},
	{Values{"q": {[]byte("puppies")}, "oe": {[]byte("utf8")}}, "oe=utf8&q=puppies"},
	{Values{"q": {[]byte("dogs"), []byte("&"), []byte("7")}}, "q=dogs&q=%26&q=7"},
	{Values{
		"a": {[]byte("a1"), []byte("a2"), []byte("a3")},
		"b": {[]byte("b1"), []byte("b2"), []byte("b3")},
		"c": {[]byte("c1"), []byte("c2"), []byte("c3")},
	}, "a=a1&a=a2&a=a3&b=b1&b=b2&b=b3&c=c1&c=c2&c=c3"},
}

func TestEncodeQuery(t *testing.T) {
	for _, tt := range encodeQueryTests {
		if q := tt.m.Encode(); q != tt.expected {
			t.Errorf(`EncodeQuery(%+v) = %q, want %q`, tt.m, q, tt.expected)
		}
	}
}

var resolvePathTests = []struct {
	base, ref, expected []byte
}{
	{[]byte("a/b"), []byte("."), []byte("/a/")},
	{[]byte("a/b"), []byte("c"), []byte("/a/c")},
	{[]byte("a/b"), []byte(".."), []byte("/")},
	{[]byte("a/"), []byte(".."), []byte("/")},
	{[]byte("a/"), []byte("../.."), []byte("/")},
	{[]byte("a/b/c"), []byte(".."), []byte("/a/")},
	{[]byte("a/b/c"), []byte("../d"), []byte("/a/d")},
	{[]byte("a/b/c"), []byte(".././d"), []byte("/a/d")},
	{[]byte("a/b"), []byte("./.."), []byte("/")},
	{[]byte("a/./b"), []byte("."), []byte("/a/")},
	{[]byte("a/../"), []byte("."), []byte("/")},
	{[]byte("a/.././b"), []byte("c"), []byte("/c")},
}

func TestResolvePath(t *testing.T) {
	for _, test := range resolvePathTests {
		got := resolvePath(test.base, test.ref)
		if bytes.Compare(got, test.expected) != 0 {
			t.Errorf("For %q + %q got %q; expected %q", test.base, test.ref, got, test.expected)
		}
	}
}

var resolveReferenceTests = []struct {
	base, rel, expected []byte
}{
	// Absolute URL references
	{[]byte("http://foo.com?a=b"), []byte("https://bar.com/"), []byte("https://bar.com/")},
	{[]byte("http://foo.com/"), []byte("https://bar.com/?a=b"), []byte("https://bar.com/?a=b")},
	{[]byte("http://foo.com/bar"), []byte("mailto:foo@example.com"), []byte("mailto:foo@example.com")},

	// Path-absolute references
	{[]byte("http://foo.com/bar"), []byte("/baz"), []byte("http://foo.com/baz")},
	{[]byte("http://foo.com/bar?a=b#f"), []byte("/baz"), []byte("http://foo.com/baz")},
	{[]byte("http://foo.com/bar?a=b"), []byte("/baz?c=d"), []byte("http://foo.com/baz?c=d")},

	// Scheme-relative
	{[]byte("https://foo.com/bar?a=b"), []byte("//bar.com/quux"), []byte("https://bar.com/quux")},

	// Path-relative references:

	// ... current directory
	{[]byte("http://foo.com"), []byte("."), []byte("http://foo.com/")},
	{[]byte("http://foo.com/bar"), []byte("."), []byte("http://foo.com/")},
	{[]byte("http://foo.com/bar/"), []byte("."), []byte("http://foo.com/bar/")},

	// ... going down
	{[]byte("http://foo.com"), []byte("bar"), []byte("http://foo.com/bar")},
	{[]byte("http://foo.com/"), []byte("bar"), []byte("http://foo.com/bar")},
	{[]byte("http://foo.com/bar/baz"), []byte("quux"), []byte("http://foo.com/bar/quux")},

	// ... going up
	{[]byte("http://foo.com/bar/baz"), []byte("../quux"), []byte("http://foo.com/quux")},
	{[]byte("http://foo.com/bar/baz"), []byte("../../../../../quux"), []byte("http://foo.com/quux")},
	{[]byte("http://foo.com/bar"), []byte(".."), []byte("http://foo.com/")},
	{[]byte("http://foo.com/bar/baz"), []byte("./.."), []byte("http://foo.com/")},
	// ".." in the middle (issue 3560)
	{[]byte("http://foo.com/bar/baz"), []byte("quux/dotdot/../tail"), []byte("http://foo.com/bar/quux/tail")},
	{[]byte("http://foo.com/bar/baz"), []byte("quux/./dotdot/../tail"), []byte("http://foo.com/bar/quux/tail")},
	{[]byte("http://foo.com/bar/baz"), []byte("quux/./dotdot/.././tail"), []byte("http://foo.com/bar/quux/tail")},
	{[]byte("http://foo.com/bar/baz"), []byte("quux/./dotdot/./../tail"), []byte("http://foo.com/bar/quux/tail")},
	{[]byte("http://foo.com/bar/baz"), []byte("quux/./dotdot/dotdot/././../../tail"), []byte("http://foo.com/bar/quux/tail")},
	{[]byte("http://foo.com/bar/baz"), []byte("quux/./dotdot/dotdot/./.././../tail"), []byte("http://foo.com/bar/quux/tail")},
	{[]byte("http://foo.com/bar/baz"), []byte("quux/./dotdot/dotdot/dotdot/./../../.././././tail"), []byte("http://foo.com/bar/quux/tail")},
	{[]byte("http://foo.com/bar/baz"), []byte("quux/./dotdot/../dotdot/../dot/./tail/.."), []byte("http://foo.com/bar/quux/dot/")},

	// Remove any dot-segments prior to forming the target URI.
	// http://tools.ietf.org/html/rfc3986#section-5.2.4
	{[]byte("http://foo.com/dot/./dotdot/../foo/bar"), []byte("../baz"), []byte("http://foo.com/dot/baz")},

	// Triple dot isn't special
	{[]byte("http://foo.com/bar"), []byte("..."), []byte("http://foo.com/...")},

	// Fragment
	{[]byte("http://foo.com/bar"), []byte(".#frag"), []byte("http://foo.com/#frag")},

	// RFC 3986: Normal Examples
	// http://tools.ietf.org/html/rfc3986#section-5.4.1
	{[]byte("http://a/b/c/d;p?q"), []byte("g:h"), []byte("g:h")},
	{[]byte("http://a/b/c/d;p?q"), []byte("g"), []byte("http://a/b/c/g")},
	{[]byte("http://a/b/c/d;p?q"), []byte("./g"), []byte("http://a/b/c/g")},
	{[]byte("http://a/b/c/d;p?q"), []byte("g/"), []byte("http://a/b/c/g/")},
	{[]byte("http://a/b/c/d;p?q"), []byte("/g"), []byte("http://a/g")},
	{[]byte("http://a/b/c/d;p?q"), []byte("//g"), []byte("http://g")},
	{[]byte("http://a/b/c/d;p?q"), []byte("?y"), []byte("http://a/b/c/d;p?y")},
	{[]byte("http://a/b/c/d;p?q"), []byte("g?y"), []byte("http://a/b/c/g?y")},
	{[]byte("http://a/b/c/d;p?q"), []byte("#s"), []byte("http://a/b/c/d;p?q#s")},
	{[]byte("http://a/b/c/d;p?q"), []byte("g#s"), []byte("http://a/b/c/g#s")},
	{[]byte("http://a/b/c/d;p?q"), []byte("g?y#s"), []byte("http://a/b/c/g?y#s")},
	{[]byte("http://a/b/c/d;p?q"), []byte(";x"), []byte("http://a/b/c/;x")},
	{[]byte("http://a/b/c/d;p?q"), []byte("g;x"), []byte("http://a/b/c/g;x")},
	{[]byte("http://a/b/c/d;p?q"), []byte("g;x?y#s"), []byte("http://a/b/c/g;x?y#s")},
	{[]byte("http://a/b/c/d;p?q"), []byte(""), []byte("http://a/b/c/d;p?q")},
	{[]byte("http://a/b/c/d;p?q"), []byte("."), []byte("http://a/b/c/")},
	{[]byte("http://a/b/c/d;p?q"), []byte("./"), []byte("http://a/b/c/")},
	{[]byte("http://a/b/c/d;p?q"), []byte(".."), []byte("http://a/b/")},
	{[]byte("http://a/b/c/d;p?q"), []byte("../"), []byte("http://a/b/")},
	{[]byte("http://a/b/c/d;p?q"), []byte("../g"), []byte("http://a/b/g")},
	{[]byte("http://a/b/c/d;p?q"), []byte("../.."), []byte("http://a/")},
	{[]byte("http://a/b/c/d;p?q"), []byte("../../"), []byte("http://a/")},
	{[]byte("http://a/b/c/d;p?q"), []byte("../../g"), []byte("http://a/g")},

	// RFC 3986: Abnormal Examples
	// http://tools.ietf.org/html/rfc3986#section-5.4.2
	{[]byte("http://a/b/c/d;p?q"), []byte("../../../g"), []byte("http://a/g")},
	{[]byte("http://a/b/c/d;p?q"), []byte("../../../../g"), []byte("http://a/g")},
	{[]byte("http://a/b/c/d;p?q"), []byte("/./g"), []byte("http://a/g")},
	{[]byte("http://a/b/c/d;p?q"), []byte("/../g"), []byte("http://a/g")},
	{[]byte("http://a/b/c/d;p?q"), []byte("g."), []byte("http://a/b/c/g.")},
	{[]byte("http://a/b/c/d;p?q"), []byte(".g"), []byte("http://a/b/c/.g")},
	{[]byte("http://a/b/c/d;p?q"), []byte("g.."), []byte("http://a/b/c/g..")},
	{[]byte("http://a/b/c/d;p?q"), []byte("..g"), []byte("http://a/b/c/..g")},
	{[]byte("http://a/b/c/d;p?q"), []byte("./../g"), []byte("http://a/b/g")},
	{[]byte("http://a/b/c/d;p?q"), []byte("./g/."), []byte("http://a/b/c/g/")},
	{[]byte("http://a/b/c/d;p?q"), []byte("g/./h"), []byte("http://a/b/c/g/h")},
	{[]byte("http://a/b/c/d;p?q"), []byte("g/../h"), []byte("http://a/b/c/h")},
	{[]byte("http://a/b/c/d;p?q"), []byte("g;x=1/./y"), []byte("http://a/b/c/g;x=1/y")},
	{[]byte("http://a/b/c/d;p?q"), []byte("g;x=1/../y"), []byte("http://a/b/c/y")},
	{[]byte("http://a/b/c/d;p?q"), []byte("g?y/./x"), []byte("http://a/b/c/g?y/./x")},
	{[]byte("http://a/b/c/d;p?q"), []byte("g?y/../x"), []byte("http://a/b/c/g?y/../x")},
	{[]byte("http://a/b/c/d;p?q"), []byte("g#s/./x"), []byte("http://a/b/c/g#s/./x")},
	{[]byte("http://a/b/c/d;p?q"), []byte("g#s/../x"), []byte("http://a/b/c/g#s/../x")},

	// Extras.
	{[]byte("https://a/b/c/d;p?q"), []byte("//g?q"), []byte("https://g?q")},
	{[]byte("https://a/b/c/d;p?q"), []byte("//g#s"), []byte("https://g#s")},
	{[]byte("https://a/b/c/d;p?q"), []byte("//g/d/e/f?y#s"), []byte("https://g/d/e/f?y#s")},
	{[]byte("https://a/b/c/d;p#s"), []byte("?y"), []byte("https://a/b/c/d;p?y")},
	{[]byte("https://a/b/c/d;p?q#s"), []byte("?y"), []byte("https://a/b/c/d;p?y")},
}

func TestResolveReference(t *testing.T) {
	mustParse := func(url []byte) *URL {
		u, err := Parse(url)
		if err != nil {
			t.Fatalf("Expected URL to parse: %q, got error: %v", url, err)
		}
		return u
	}
	opaque := &URL{Scheme: []byte("scheme"), Opaque: []byte("opaque")}
	for _, test := range resolveReferenceTests {
		base := mustParse(test.base)
		rel := mustParse(test.rel)
		url := base.ResolveReference(rel)
		if bytes.Compare(url.Bytes(), test.expected) != 0 {
			t.Errorf("URL(%q).ResolveReference(%q) == %q, got %q", test.base, test.rel, test.expected, url.String())
		}
		// Ensure that new instances are returned.
		if base == url {
			t.Errorf("Expected URL.ResolveReference to return new URL instance.")
		}
		// Test the convenience wrapper too.
		url, err := base.Parse(test.rel)
		if err != nil {
			t.Errorf("URL(%q).Parse(%q) failed: %v", test.base, test.rel, err)
		} else if bytes.Compare(url.Bytes(), test.expected) != 0 {
			t.Errorf("URL(%q).Parse(%q) == %q, got %q", test.base, test.rel, test.expected, url.String())
		} else if base == url {
			// Ensure that new instances are returned for the wrapper too.
			t.Errorf("Expected URL.Parse to return new URL instance.")
		}
		// Ensure Opaque resets the URL.
		url = base.ResolveReference(opaque)
		if reflect.DeepEqual(*url, *opaque) {
			t.Errorf("ResolveReference failed to resolve opaque URL: want %#v, got %#v", url, opaque)
		}
		// Test the convenience wrapper with an opaque URL too.
		url, err = base.Parse([]byte("scheme:opaque"))
		if err != nil {
			t.Errorf(`URL(%q).Parse("scheme:opaque") failed: %v`, test.base, err)
		} else if reflect.DeepEqual(*url, *opaque) {
			t.Errorf("Parse failed to resolve opaque URL: want %#v, got %#v", url, opaque)
		} else if base == url {
			// Ensure that new instances are returned, again.
			t.Errorf("Expected URL.Parse to return new URL instance.")
		}
	}
}

func TestQueryValues(t *testing.T) {
	u, _ := Parse([]byte("http://x.com?foo=bar&bar=1&bar=2"))
	v := u.Query()
	if len(v) != 2 {
		t.Errorf("got %d keys in Query values, want 2", len(v))
	}
	if g, e := v.Get("foo"), "bar"; string(g) != e {
		t.Errorf("Get(foo) = %q, want %q", g, e)
	}
	// Case sensitive:
	if g, e := v.Get("Foo"), ""; string(g) != e {
		t.Errorf("Get(Foo) = %q, want %q", g, e)
	}
	if g, e := v.Get("bar"), "1"; string(g) != e {
		t.Errorf("Get(bar) = %q, want %q", g, e)
	}
	if g, e := v.Get("baz"), ""; string(g) != e {
		t.Errorf("Get(baz) = %q, want %q", g, e)
	}
	v.Del("bar")
	if g, e := v.Get("bar"), ""; string(g) != e {
		t.Errorf("second Get(bar) = %q, want %q", g, e)
	}
}

type parseTest struct {
	query []byte
	out   Values
}

var parseTests = []parseTest{
	{
		query: []byte("a=1&b=2"),
		out:   Values{"a": [][]byte{[]byte("1")}, "b": [][]byte{[]byte("2")}},
	},
	{
		query: []byte("a=1&a=2&a=banana"),
		out:   Values{"a": [][]byte{[]byte("1"), []byte("2"), []byte("banana")}},
	},
	{
		query: []byte("ascii=%3Ckey%3A+0x90%3E"),
		out:   Values{"ascii": [][]byte{[]byte("<key: 0x90>")}},
	},
	{
		query: []byte("a=1;b=2"),
		out:   Values{"a": [][]byte{[]byte("1")}, "b": [][]byte{[]byte("2")}},
	},
	{
		query: []byte("a=1&a=2;a=banana"),
		out:   Values{"a": [][]byte{[]byte("1"), []byte("2"), []byte("banana")}},
	},
}

func TestParseQuery(t *testing.T) {
	for i, test := range parseTests {
		form, err := ParseQuery(test.query)
		if err != nil {
			t.Errorf("test %d: Unexpected error: %v", i, err)
			continue
		}
		if len(form) != len(test.out) {
			t.Errorf("test %d: len(form) = %d, want %d", i, len(form), len(test.out))
		}
		for k, evs := range test.out {
			vs, ok := form[k]
			if !ok {
				t.Errorf("test %d: Missing key %q", i, k)
				continue
			}
			if len(vs) != len(evs) {
				t.Errorf("test %d: len(form[%q]) = %d, want %d", i, k, len(vs), len(evs))
				continue
			}
			for j, ev := range evs {
				if v := vs[j]; bytes.Compare(v, ev) != 0 {
					t.Errorf("test %d: form[%q][%d] = %q, want %q", i, k, j, v, ev)
				}
			}
		}
	}
}

type RequestURITest struct {
	url *URL
	out []byte
}

var requritests = []RequestURITest{
	{
		&URL{
			Scheme: []byte("http"),
			Host:   []byte("example.com"),
			Path:   []byte(""),
		},
		[]byte("/"),
	},
	{
		&URL{
			Scheme: []byte("http"),
			Host:   []byte("example.com"),
			Path:   []byte("/a b"),
		},
		[]byte("/a%20b"),
	},
	// golang.org/issue/4860 variant 1
	{
		&URL{
			Scheme: []byte("http"),
			Host:   []byte("example.com"),
			Opaque: []byte("/%2F/%2F/"),
		},
		[]byte("/%2F/%2F/"),
	},
	// golang.org/issue/4860 variant 2
	{
		&URL{
			Scheme: []byte("http"),
			Host:   []byte("example.com"),
			Opaque: []byte("//other.example.com/%2F/%2F/"),
		},
		[]byte("http://other.example.com/%2F/%2F/"),
	},
	{
		&URL{
			Scheme:   []byte("http"),
			Host:     []byte("example.com"),
			Path:     []byte("/a b"),
			RawQuery: []byte("q=go+language"),
		},
		[]byte("/a%20b?q=go+language"),
	},
	{
		&URL{
			Scheme: []byte("myschema"),
			Opaque: []byte("opaque"),
		},
		[]byte("opaque"),
	},
	{
		&URL{
			Scheme:   []byte("myschema"),
			Opaque:   []byte("opaque"),
			RawQuery: []byte("q=go+language"),
		},
		[]byte("opaque?q=go+language"),
	},
}

func TestRequestURI(t *testing.T) {
	for _, tt := range requritests {
		s := tt.url.RequestURI()
		if bytes.Compare(s, tt.out) != 0 {
			t.Errorf("%#v.RequestURI() == %q (expected %q)", tt.url, s, tt.out)
		}
	}
}

func TestParseFailure(t *testing.T) {
	// Test that the first parse error is returned.
	var url = []byte("%gh&%ij")
	_, err := ParseQuery(url)
	errStr := fmt.Sprint(err)
	if !strings.Contains(errStr, "%gh") {
		t.Errorf(`ParseQuery(%q) returned error %q, want something containing %q"`, url, errStr, "%gh")
	}
}

type shouldEscapeTest struct {
	in     byte
	mode   encoding
	escape bool
}

var shouldEscapeTests = []shouldEscapeTest{
	// Unreserved characters (§2.3)
	{'a', encodePath, false},
	{'a', encodeUserPassword, false},
	{'a', encodeQueryComponent, false},
	{'a', encodeFragment, false},
	{'z', encodePath, false},
	{'A', encodePath, false},
	{'Z', encodePath, false},
	{'0', encodePath, false},
	{'9', encodePath, false},
	{'-', encodePath, false},
	{'-', encodeUserPassword, false},
	{'-', encodeQueryComponent, false},
	{'-', encodeFragment, false},
	{'.', encodePath, false},
	{'_', encodePath, false},
	{'~', encodePath, false},

	// User information (§3.2.1)
	{':', encodeUserPassword, true},
	{'/', encodeUserPassword, true},
	{'?', encodeUserPassword, true},
	{'@', encodeUserPassword, true},
	{'$', encodeUserPassword, false},
	{'&', encodeUserPassword, false},
	{'+', encodeUserPassword, false},
	{',', encodeUserPassword, false},
	{';', encodeUserPassword, false},
	{'=', encodeUserPassword, false},
}

func TestShouldEscape(t *testing.T) {
	for _, tt := range shouldEscapeTests {
		if shouldEscape(tt.in, tt.mode) != tt.escape {
			t.Errorf("shouldEscape(%q, %v) returned %v; expected %v", tt.in, tt.mode, !tt.escape, tt.escape)
		}
	}
}
