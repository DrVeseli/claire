package main

import (
	"net"
	"os"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestSanitizeRoundTrip(t *testing.T) {
	raw := "2026-09-29T15:58:47Z user=marko email marko@example.com at /home/marko/private/app.log\n" +
		"device_id=ABC123456789 session '3h0gfkyvupwm19kudfd5byakk0' private=172.19.0.17 public=8.8.8.8 v6=2001:db8:1::9\n" +
		"uuid cf870917-9dbe-4576-8b12-8d1028b24fa4 mac aa:bb:cc:dd:ee:ff https://private.example.com:443/api/export-users-csv\n" +
		"parseIPv6Reference [cbadmin, session: cf870917-9dbe-4576-8b12-8d1028b24fa4] project u_cbadmin\n" +
		"path /opt/cloudbeaver/workspace/private.log host https://cloudbeaver.private.example:443\n"
	safe, key := Sanitize(raw)
	for _, secret := range []string{"marko@example.com", "/home/marko/", "ABC123456789", "172.19.0.17", "private.example.com", "cf870917-9dbe-4576-8b12-8d1028b24fa4"} {
		if strings.Contains(safe, secret) {
			t.Errorf("sanitized output still contains %q", secret)
		}
	}
	if !strings.Contains(safe, "2026-09-29T15:58:47Z") || !strings.Contains(safe, "export-users-csv") {
		t.Errorf("sanitizer changed timestamp or ordinary API path: %q", safe)
	}
	if !strings.Contains(safe, "parseIPv6Reference") || strings.Contains(safe, "cbadmin") {
		t.Errorf("sanitizer changed a method name or leaked a contextual user: %q", safe)
	}
	if strings.Count(safe, "cloudbeaver") != strings.Count(raw, "cloudbeaver") || !strings.Contains(safe, "/opt/cloudbeaver/item-") {
		t.Errorf("sanitizer did not preserve cloudbeaver: %q", safe)
	}
	for _, entry := range key.Entries {
		if entry.Kind == "ipv4" {
			original, alias := net.ParseIP(entry.Original), net.ParseIP(entry.Alias)
			if alias == nil || original.IsPrivate() != alias.IsPrivate() {
				t.Errorf("IPv4 scope changed: %q -> %q", entry.Original, entry.Alias)
			}
		}
		if entry.Kind == "ipv6" && net.ParseIP(entry.Alias) == nil {
			t.Errorf("invalid IPv6 alias %q", entry.Alias)
		}
	}
	restored, err := Restore(safe, key)
	if err != nil {
		t.Fatal(err)
	}
	if restored != raw {
		t.Fatalf("round trip mismatch\nwant: %q\n got: %q", raw, restored)
	}

	tampered := safe + "changed"
	if _, err := Restore(tampered, key); err == nil {
		t.Fatal("expected mismatched key error")
	}
}

func TestKeyPermissions(t *testing.T) {
	path := t.TempDir() + "/key.txt"
	if err := WriteKey(path, Key{Version: 1}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("key permissions are %o, want 600", info.Mode().Perm())
	}
}

func TestSeverityInheritance(t *testing.T) {
	levels := classify([]string{"x ERROR broke", "\tat stack", "x INFO recovered"})
	if levels[0] != errorLevel || levels[1] != errorLevel || levels[2] != info {
		t.Fatalf("unexpected levels: %v", levels)
	}
}

func TestViewerFiltersAndPreview(t *testing.T) {
	m := newModel("test.log", "x ERROR raw\nx INFO ok", "x ERROR safe\nx INFO ok")
	m.width, m.height = 80, 10
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	m = updated.(model)
	if got := m.visible(); len(got) != 1 || got[0] != 0 {
		t.Fatalf("errors-only filter returned %v", got)
	}
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	m = updated.(model)
	if m.sanitized || !strings.Contains(m.View(), "raw") {
		t.Fatal("raw preview did not switch")
	}
}
