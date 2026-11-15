package auth

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
)

// secureURL rejects ambiguous endpoints before any credentials can be attached.
func secureURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || strings.Contains(raw, "#") || u.Opaque != "" {
		return nil, errors.New("registry endpoint must be an absolute HTTPS URL without userinfo or fragment")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, errors.New("invalid registry endpoint port")
		}
	}
	if _, err := url.ParseQuery(u.RawQuery); err != nil {
		return nil, errors.New("invalid registry endpoint query")
	}
	return u, nil
}

// Only the scheme and parameter names are case insensitive; values are opaque.
func parseChallenge(challenge string) (map[string]string, error) {
	if len(challenge) > 16384 || strings.ContainsAny(challenge, "\r\n\x00") {
		return nil, errors.New("invalid registry challenge")
	}
	scheme, raw, ok := strings.Cut(strings.TrimSpace(challenge), " ")
	if !ok || !strings.EqualFold(scheme, "bearer") {
		return nil, errors.New("unsupported registry challenge")
	}
	values := make(map[string]string)
	for raw = strings.TrimSpace(raw); raw != ""; raw = strings.TrimSpace(raw) {
		raw = strings.TrimLeft(raw, ", ")
		if raw == "" {
			break
		}
		end := strings.IndexAny(raw, "=,")
		if end < 0 {
			break
		} // Ignore legacy valueless extensions.
		if raw[end] == ',' {
			raw = raw[end+1:]
			continue
		}
		key := strings.ToLower(strings.TrimSpace(raw[:end]))
		raw = strings.TrimSpace(raw[end+1:])
		var value string
		if strings.HasPrefix(raw, `"`) {
			raw = raw[1:]
			var b strings.Builder
			closed := false
			for len(raw) > 0 {
				ch := raw[0]
				raw = raw[1:]
				if ch == '"' {
					closed = true
					break
				}
				if ch == '\\' {
					if len(raw) == 0 {
						break
					}
					ch = raw[0]
					raw = raw[1:]
				}
				b.WriteByte(ch)
			}
			if !closed {
				return nil, errors.New("unterminated registry challenge value")
			}
			value = b.String()
			if s := strings.TrimSpace(raw); s != "" && s[0] != ',' {
				return nil, errors.New("invalid registry challenge separator")
			}
		} else {
			value, raw, _ = strings.Cut(raw, ",")
			value = strings.TrimSpace(value)
		}
		if _, exists := values[key]; exists {
			return nil, errors.New("duplicate registry challenge parameter")
		}
		values[key] = value
	}
	return values, nil
}
