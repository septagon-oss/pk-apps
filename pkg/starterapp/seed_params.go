// Implements: REQ-005.
// Per: ADR-0009.
// Discipline: C-14.

// seed_params.go maps the app Config onto the first-boot seed parameters. It is
// where the development-only default credential is confined: outside a
// development environment the admin password must be supplied via
// seed.admin_password, and it is never re-asserted on later boots. This is the
// composition-layer half of closing the v0.1.0 seed-password backdoor.
//
// ADR: ADR-0009 (ports-only module communication), ADR-0029 (file purpose declaration).
// Convention: C-14 (every Go file declares its purpose).
package starterapp

import (
	"fmt"

	"github.com/septagon-oss/pk-apps/pkg/starterapp/seed"
)

// resolveSeedParams derives the seed parameters from configuration. In a
// development environment it falls back to the local bootstrap identity and
// enables password self-repair. In any other environment seed.admin_password
// is REQUIRED and the password is never re-asserted, so an operator's changed
// credential survives a restart.
func resolveSeedParams(cfg *Config) (seed.Params, error) {
	email := cfg.Seed.AdminEmail
	if email == "" {
		email = seed.UserEmail
	}
	dev := cfg.Environment == "development"
	password := cfg.Seed.AdminPassword
	if password == "" {
		if !dev {
			return seed.Params{}, fmt.Errorf(
				"starterapp: seed.admin_password is required when environment is %q "+
					"(only \"development\" may use the local bootstrap password)", cfg.Environment)
		}
		password = seed.UserPass
	}
	return seed.Params{
		AdminEmail:     email,
		AdminPassword:  password,
		RepairPassword: dev,
	}, nil
}

// seedBannerCredential returns what the development-only startup banner may
// show for the local login. Outside development both fields are redacted; the
// public root page never renders either value.
func seedBannerCredential(cfg *Config, params seed.Params) (email, password string) {
	if cfg.Environment == "development" {
		return params.AdminEmail, params.AdminPassword
	}
	return "(see seed.admin_email)", "(set via seed.admin_password)"
}
