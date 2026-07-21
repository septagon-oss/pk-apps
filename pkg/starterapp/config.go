// Implements: REQ-010.
// Per: ADR-0005.
// Discipline: C-14.

// Package starterapp — config.go owns the small typed configuration surface for
// the starter monolith plus the YAML loader used by binary wrappers.
//
// We use a hand-written line-oriented parser instead of importing a YAML
// dependency. The config schema is intentionally narrow: a handful of strings
// and durations under three sections (http, database, cache) plus three
// top-level fields. The parser is tolerant of comments, blank lines, and
// trailing whitespace and rejects unknown keys to keep typos loud.
//
// DefaultConfig is exported so a wrapper can boot the starter with zero config
// files (the front-door repo relies on this), and LoadConfig is exported so a
// wrapper that ships a config.yaml can opt into it.
//
// ADR: ADR-0029 (file purpose declaration).
// Convention: C-14 (every Go file declares its purpose).
package starterapp

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

// Config is the parsed contents of a starter config.yaml.
type Config struct {
	AppName     string
	AppVersion  string
	Environment string

	HTTP     HTTPConfig
	Database DatabaseConfig
	Cache    CacheConfig
	Seed     SeedConfig
}

// HTTPConfig models the http: block.
type HTTPConfig struct {
	Addr            string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	ShutdownTimeout time.Duration
}

// DatabaseConfig models the database: block.
type DatabaseConfig struct {
	Driver string
	DSN    string
}

// CacheConfig models the cache: block.
type CacheConfig struct {
	Provider string
}

// SeedConfig models the seed: block — the first-boot admin credentials. In a
// development environment these default to the demo login when unset. Outside
// development, admin_password is REQUIRED (BuildApp refuses to boot without it)
// so the starter never ships a hardcoded, re-asserted default password.
type SeedConfig struct {
	AdminEmail    string
	AdminPassword string
}

// DefaultConfig returns the runtime defaults used when a key is missing — and a
// complete, bootable config on its own when no config.yaml is present.
func DefaultConfig() *Config {
	return &Config{
		AppName:     "starter-saas",
		AppVersion:  "0.1.0",
		Environment: "development",
		HTTP: HTTPConfig{
			Addr:            ":8080",
			ReadTimeout:     30 * time.Second,
			WriteTimeout:    30 * time.Second,
			ShutdownTimeout: 30 * time.Second,
		},
		Database: DatabaseConfig{
			Driver: "sqlite",
			// _pragma=busy_timeout(5000) makes a busy/locked database wait up to
			// 5s for the lock instead of immediately returning SQLITE_BUSY — the
			// modernc.org/sqlite-correct form of the busy_timeout pragma. This
			// de-risks transient contention on the single shared pk.db file.
			DSN: "file:./pk.db?_pragma=busy_timeout(5000)&cache=shared&mode=rwc",
		},
		Cache: CacheConfig{
			Provider: "memory",
		},
	}
}

// LoadConfig reads config.yaml from path and returns a populated Config. Any
// key that does not appear in the file is left at the default value. A missing
// file is not an error: defaults are returned so the starter still boots.
//
// Security note: when a config file IS present, an omitted `environment:` key
// defaults to "production", NOT to the development default. Writing a config
// file signals a real deployment, and the development default silently enables
// a re-asserted demo password — so an operator who provides a config but
// forgets to declare the environment fails closed (production requires
// seed.admin_password) rather than silently running the demo credential. The
// zero-config demo path (DefaultConfig with no file) stays development.
func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Missing config is acceptable for the demo — defaults will boot.
			return cfg, nil
		}
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	// A present config file is a deployment signal: fail closed on environment
	// unless the file explicitly declares it. The file's `environment:` key (if
	// any) overrides this during parsing below.
	cfg.Environment = "production"

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 16*1024), 1<<20)

	section := ""
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		raw := scanner.Text()
		line := stripComment(raw)
		if strings.TrimSpace(line) == "" {
			continue
		}
		indented := len(line) > 0 && (line[0] == ' ' || line[0] == '\t')
		key, value, ok := splitKV(line)
		if !ok {
			return nil, fmt.Errorf("config %s:%d: invalid line %q", path, lineNum, raw)
		}
		if value == "" {
			// Section header (`http:`, `database:`, etc.).
			section = key
			continue
		}
		if !indented {
			section = ""
		}
		if err := applyConfig(cfg, section, key, value); err != nil {
			return nil, fmt.Errorf("config %s:%d: %w", path, lineNum, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return cfg, nil
}

// stripComment removes everything from the first unquoted '#' onward.
func stripComment(line string) string {
	inQuote := false
	for i, r := range line {
		if r == '"' {
			inQuote = !inQuote
			continue
		}
		if r == '#' && !inQuote {
			return line[:i]
		}
	}
	return line
}

// splitKV parses a "key: value" line, stripping the surrounding whitespace
// from both sides.
func splitKV(line string) (string, string, bool) {
	before, after, ok := strings.Cut(line, ":")
	if !ok {
		return "", "", false
	}
	key := strings.TrimSpace(before)
	value := strings.TrimSpace(after)
	value = strings.Trim(value, "\"")
	if key == "" {
		return "", "", false
	}
	return key, value, true
}

// applyConfig sets one (section, key, value) triple on the Config.
func applyConfig(cfg *Config, section, key, value string) error {
	switch section {
	case "":
		switch key {
		case "app_name":
			cfg.AppName = value
		case "app_version":
			cfg.AppVersion = value
		case "environment":
			cfg.Environment = value
		default:
			return fmt.Errorf("unknown top-level key %q", key)
		}
	case "http":
		switch key {
		case "addr":
			cfg.HTTP.Addr = value
		case "read_timeout":
			d, err := time.ParseDuration(value)
			if err != nil {
				return fmt.Errorf("http.read_timeout: %w", err)
			}
			cfg.HTTP.ReadTimeout = d
		case "write_timeout":
			d, err := time.ParseDuration(value)
			if err != nil {
				return fmt.Errorf("http.write_timeout: %w", err)
			}
			cfg.HTTP.WriteTimeout = d
		case "shutdown_timeout":
			d, err := time.ParseDuration(value)
			if err != nil {
				return fmt.Errorf("http.shutdown_timeout: %w", err)
			}
			cfg.HTTP.ShutdownTimeout = d
		default:
			return fmt.Errorf("unknown http key %q", key)
		}
	case "seed":
		switch key {
		case "admin_email":
			cfg.Seed.AdminEmail = value
		case "admin_password":
			cfg.Seed.AdminPassword = value
		default:
			return fmt.Errorf("unknown seed key %q", key)
		}
	case "database":
		switch key {
		case "driver":
			cfg.Database.Driver = value
		case "dsn":
			cfg.Database.DSN = value
		default:
			return fmt.Errorf("unknown database key %q", key)
		}
	case "cache":
		switch key {
		case "provider":
			cfg.Cache.Provider = value
		default:
			return fmt.Errorf("unknown cache key %q", key)
		}
	default:
		return fmt.Errorf("unknown section %q", section)
	}
	return nil
}
