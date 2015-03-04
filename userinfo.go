package bytesurl

import "bytes"

// User returns a Userinfo containing the provided username
// and no password set.
func User(username []byte) *Userinfo {
	return &Userinfo{username, EmptyByte, false}
}

// UserPassword returns a Userinfo containing the provided username
// and password.
// This functionality should only be used with legacy web sites.
// RFC 2396 warns that interpreting Userinfo this way
// ``is NOT RECOMMENDED, because the passing of authentication
// information in clear text (such as URI) has proven to be a
// security risk in almost every case where it has been used.''
func UserPassword(username, password []byte) *Userinfo {
	return &Userinfo{username, password, true}
}

// The Userinfo type is an immutable encapsulation of username and
// password details for a URL. An existing Userinfo value is guaranteed
// to have a username set (potentially empty, as allowed by RFC 2396),
// and optionally a password.
type Userinfo struct {
	username    []byte
	password    []byte
	passwordSet bool
}

// Username returns the username.
func (u *Userinfo) Username() []byte {
	return u.username
}

// Password returns the password in case it is set, and whether it is set.
func (u *Userinfo) Password() ([]byte, bool) {
	if u.passwordSet {
		return u.password, true
	}
	return EmptyByte, false
}

// Bytes returns the encoded userinfo information in the standard form
// of "username[:password]".
func (u *Userinfo) Bytes() []byte {
	var buffer bytes.Buffer
	buffer.Write(escape(u.username, encodeUserPassword))
	if u.passwordSet {
		buffer.Write(ColonByte)
		buffer.Write(escape(u.password, encodeUserPassword))
	}
	return buffer.Bytes()
}

// String returns the encoded userinfo information in the standard form
// of "username[:password]".
func (u *Userinfo) String() string {
	return string(u.Bytes())
}
