// Implements: REQ-016.
// Per: ADR-0017.
// Discipline: C-14.

package starterapp

// address.go owns the environment-to-listener mapping shared by the canonical
// front door and downstream wrappers. PORT changes only the loopback port;
// listening on another interface requires an explicit PK_HTTP_ADDR.

import "strings"

// ApplyAddressOverrides applies PK_HTTP_ADDR or PORT from lookup to cfg.
// PK_HTTP_ADDR wins when both are set. A nil config or lookup is a no-op.
func ApplyAddressOverrides(cfg *Config, lookup func(string) string) {
	if cfg == nil || lookup == nil {
		return
	}
	if addr := strings.TrimSpace(lookup("PK_HTTP_ADDR")); addr != "" {
		cfg.HTTP.Addr = addr
		return
	}
	if port := strings.TrimSpace(lookup("PORT")); port != "" {
		cfg.HTTP.Addr = "127.0.0.1:" + port
	}
}
