// Package main — config.go owns the small typed configuration surface for the
// starter-saas monolith plus the YAML loader used by main().
//
// We use a hand-written line-oriented parser instead of importing a YAML
// dependency. The config schema is intentionally narrow: a handful of strings
// and durations under three sections (http, database, cache) plus three
// top-level fields. The parser is tolerant of comments, blank lines, and
// trailing whitespace and rejects unknown keys to keep typos loud.
//
// ADR: ADR-0029 (file purpose declaration).
// Convention: C-14 (every Go file declares its purpose).
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

// Config is the parsed contents of config.yaml.
type Config struct {
	AppName     string
	AppVersion  string
	Environment string

	HTTP     HTTPConfig
	Database DatabaseConfig
	Cache    CacheConfig
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

// defaultConfig returns the runtime defaults used when a key is missing.
func defaultConfig() *Config {
	return &Config{
		AppName:     "starter-saas",
		AppVersion:  "0.0.0",
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

// loadConfig reads config.yaml from path and returns a populated Config. Any
// key that does not appear in the file is left at the default value.
func loadConfig(path string) (*Config, error) {
	cfg := defaultConfig()

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Missing config is acceptable for the demo — defaults will boot.
			return cfg, nil
		}
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

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
	idx := strings.IndexByte(line, ':')
	if idx < 0 {
		return "", "", false
	}
	key := strings.TrimSpace(line[:idx])
	value := strings.TrimSpace(line[idx+1:])
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
