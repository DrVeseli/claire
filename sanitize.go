package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Entry struct {
	Kind     string `json:"kind"`
	Alias    string `json:"alias"`
	Original string `json:"original"`
}

type Key struct {
	Version         int     `json:"version"`
	SanitizedSHA256 string  `json:"sanitized_sha256"`
	Entries         []Entry `json:"entries"`
}

type sanitizer struct {
	entries []Entry
	known   map[string]string
	used    map[string]bool
	counts  map[string]int
	source  string
}

var (
	emailRE     = regexp.MustCompile(`(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b`)
	uuidRE      = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b`)
	macRE       = regexp.MustCompile(`(?i)\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b`)
	ipv4RE      = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	ipv6RE      = regexp.MustCompile(`(?i)\b[0-9a-f:]{2,}(?:%[a-z0-9_.-]+)?\b`)
	urlHostRE   = regexp.MustCompile(`(?i)(?:https?|ssh|tcp|jdbc:[a-z0-9]+)://\[?([a-z0-9][a-z0-9.-]*)(?::[0-9]+)?\]?`)
	pathRE      = regexp.MustCompile(`(^|[\s'"(\[]|file:(?://)?)(/(?:etc|home|Users|var|opt|tmp|usr|root|srv|mnt|media|data|Volumes|private)(?:/[A-Za-z0-9_.@+-]+)+/?)`)
	fieldRE     = regexp.MustCompile(`(?i)\b(device(?:[_ -]?id)?|machine(?:[_ -]?id)?|session(?:[_ -]?id)?|user(?:name|[_ -]?id)?|account(?:[_ -]?id)?|tenant(?:[_ -]?id)?|serial(?:[_ -]?(?:number|id))?|host(?:name)?|clientId|groupId)((?:[ \t]*(?::|=|\bis\b)[ \t]*|[ \t]+)['"]?)([A-Za-z0-9][A-Za-z0-9._@-]{2,})`)
	tokenRE     = regexp.MustCompile(`\b[A-Za-z0-9_-]{12,}\b`)
	dateTokenRE = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}$`)
	userRE      = regexp.MustCompile(`\[([A-Za-z][A-Za-z0-9._@-]{2,}),[ \t]+session:`)
)

func Sanitize(input string) (string, Key) {
	s := &sanitizer{
		known:  make(map[string]string),
		used:   make(map[string]bool),
		counts: make(map[string]int),
		source: input,
	}
	out := input
	for _, match := range userRE.FindAllStringSubmatch(input, -1) {
		user := match[1]
		if protected(user) {
			continue
		}
		alias := s.alias("user", user, func(n int) string { return fmt.Sprintf("user-%03d", n) })
		out = strings.ReplaceAll(out, user, alias)
	}
	out = emailRE.ReplaceAllStringFunc(out, func(v string) string {
		if protected(v) {
			return s.alias("email", v, func(n int) string { return fmt.Sprintf("cloudbeaver%d@example.invalid", n) })
		}
		return s.alias("email", v, func(n int) string { return fmt.Sprintf("person%d@example.invalid", n) })
	})
	out = uuidRE.ReplaceAllStringFunc(out, func(v string) string {
		return s.alias("uuid", v, func(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) })
	})
	out = macRE.ReplaceAllStringFunc(out, func(v string) string {
		return s.alias("mac", v, func(n int) string { return fmt.Sprintf("02:00:00:%02x:%02x:%02x", n>>16&255, n>>8&255, n&255) })
	})
	out = ipv4RE.ReplaceAllStringFunc(out, func(v string) string {
		if net.ParseIP(v) == nil || v == "0.0.0.0" || v == "127.0.0.1" {
			return v
		}
		return s.alias("ipv4", v, func(n int) string { return shapedIPv4(v, n) })
	})
	out = ipv6RE.ReplaceAllStringFunc(out, func(v string) string {
		address := strings.SplitN(v, "%", 2)[0]
		if !strings.Contains(address, ":") || net.ParseIP(address) == nil || net.ParseIP(address).IsLoopback() {
			return v
		}
		return s.alias("ipv6", v, func(n int) string { return fmt.Sprintf("2001:db8::%x", n) })
	})
	out = replaceCapture(out, urlHostRE, 1, func(v string) string {
		if v == "localhost" || net.ParseIP(v) != nil || strings.HasSuffix(v, ".invalid") {
			return v
		}
		if protected(v) {
			return s.alias("host", v, func(n int) string { return fmt.Sprintf("cloudbeaver.host-%d.invalid", n) })
		}
		return s.alias("host", v, func(n int) string { return fmt.Sprintf("host-%d.example.invalid", n) })
	})
	out = pathRE.ReplaceAllStringFunc(out, func(match string) string {
		parts := pathRE.FindStringSubmatch(match)
		return parts[1] + s.sanitizePath(parts[2])
	})
	out = replaceCapture(out, fieldRE, 3, func(v string) string {
		lower := strings.ToLower(v)
		if lower == "null" || lower == "localhost" || lower == "unauthorized" || s.used[v] {
			return v
		}
		if protected(v) {
			return s.alias("identifier", v, func(n int) string { return fmt.Sprintf("cloudbeaver-alias-%04d", n) })
		}
		return s.alias("identifier", v, func(n int) string { return fmt.Sprintf("alias-%04d", n) })
	})
	out = tokenRE.ReplaceAllStringFunc(out, func(v string) string {
		if !isOpaque(v) || s.used[v] || dateTokenRE.MatchString(v) {
			return v
		}
		if protected(v) {
			return s.alias("token", v, func(n int) string { return fmt.Sprintf("cloudbeaver-token%08d", n) })
		}
		return s.alias("token", v, func(n int) string { return fmt.Sprintf("token%08d", n) })
	})
	sum := sha256.Sum256([]byte(out))
	return out, Key{Version: 1, SanitizedSHA256: hex.EncodeToString(sum[:]), Entries: s.entries}
}

func (s *sanitizer) sanitizePath(path string) string {
	trailing := strings.HasSuffix(path, "/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i := 1; i < len(parts); i++ {
		part := parts[i]
		if protected(part) {
			continue
		}
		ext := filepath.Ext(part)
		parts[i] = s.alias("path", part, func(n int) string { return fmt.Sprintf("item-%03d%s", n, ext) })
	}
	result := "/" + strings.Join(parts, "/")
	if trailing {
		result += "/"
	}
	return result
}

func (s *sanitizer) alias(kind, original string, makeAlias func(int) string) string {
	key := kind + "\x00" + original
	if alias, ok := s.known[key]; ok {
		return alias
	}
	for {
		s.counts[kind]++
		alias := makeAlias(s.counts[kind])
		if !s.used[alias] && !strings.Contains(s.source, alias) {
			s.known[key], s.used[alias] = alias, true
			s.entries = append(s.entries, Entry{Kind: kind, Alias: alias, Original: original})
			return alias
		}
	}
}

func shapedIPv4(original string, n int) string {
	ip := net.ParseIP(original).To4()
	host, subnet := (n-1)%254+1, (n-1)/254%254
	switch {
	case ip[0] == 10:
		return fmt.Sprintf("10.255.%d.%d", subnet, host)
	case ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31:
		return fmt.Sprintf("172.31.%d.%d", subnet, host)
	case ip[0] == 192 && ip[1] == 168:
		return fmt.Sprintf("192.168.%d.%d", subnet, host)
	case ip[0] == 169 && ip[1] == 254:
		return fmt.Sprintf("169.254.%d.%d", subnet, host)
	}
	return documentationIPv4(n)
}

func documentationIPv4(n int) string {
	ranges := [][3]int{{192, 0, 2}, {198, 51, 100}, {203, 0, 113}}
	n--
	block, host := (n/254)%len(ranges), n%254+1
	r := ranges[block]
	return fmt.Sprintf("%d.%d.%d.%d", r[0], r[1], r[2], host)
}

func protected(s string) bool {
	return strings.Contains(strings.ToLower(s), "cloudbeaver")
}

func replaceCapture(input string, re *regexp.Regexp, group int, replace func(string) string) string {
	matches := re.FindAllStringSubmatchIndex(input, -1)
	if len(matches) == 0 {
		return input
	}
	var out strings.Builder
	last := 0
	for _, match := range matches {
		start, end := match[group*2], match[group*2+1]
		if start < 0 {
			continue
		}
		out.WriteString(input[last:start])
		out.WriteString(replace(input[start:end]))
		last = end
	}
	out.WriteString(input[last:])
	return out.String()
}

func hasLetterAndDigit(s string) bool {
	letter, digit := false, false
	for _, r := range s {
		letter = letter || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
		digit = digit || r >= '0' && r <= '9'
	}
	return letter && digit
}

func isOpaque(s string) bool {
	if !hasLetterAndDigit(s) {
		return false
	}
	if len(s) >= 20 {
		return true
	}
	allHex, hasLower := true, false
	for _, r := range s {
		allHex = allHex && (r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F')
		hasLower = hasLower || r >= 'a' && r <= 'z'
	}
	return allHex || !hasLower
}

func Restore(sanitized string, key Key) (string, error) {
	if key.Version != 1 {
		return "", fmt.Errorf("unsupported key version %d", key.Version)
	}
	if key.SanitizedSHA256 != "" {
		sum := sha256.Sum256([]byte(sanitized))
		if hex.EncodeToString(sum[:]) != key.SanitizedSHA256 {
			return "", errors.New("key does not match this sanitized log")
		}
	}
	seen := make(map[string]bool, len(key.Entries))
	for _, entry := range key.Entries {
		if entry.Alias == "" || seen[entry.Alias] {
			return "", errors.New("key contains an empty or duplicate alias")
		}
		seen[entry.Alias] = true
	}
	for i := len(key.Entries) - 1; i >= 0; i-- {
		entry := key.Entries[i]
		sanitized = strings.ReplaceAll(sanitized, entry.Alias, entry.Original)
	}
	return sanitized, nil
}

func WriteKey(path string, key Key) error {
	data, err := json.MarshalIndent(key, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeAtomic(path, data, 0600)
}

func ReadKey(path string) (Key, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Key{}, err
	}
	var key Key
	if err := json.Unmarshal(data, &key); err != nil {
		return Key{}, fmt.Errorf("invalid key: %w", err)
	}
	return key, nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".claire-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
