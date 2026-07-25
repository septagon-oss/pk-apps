module github.com/septagon-oss/pk-apps

go 1.26

require (
	github.com/septagon-oss/pk-core v0.1.0
	github.com/septagon-oss/pk-design v0.2.0
	github.com/septagon-oss/pk-modules v0.11.0
	github.com/septagon-oss/pk-runtime v0.1.0
	github.com/septagon-oss/pk-ui v0.1.1
	github.com/septagon-oss/styleengine v0.1.0
	github.com/septagon-oss/tw v0.2.2
	maragu.dev/gomponents v1.3.0
	modernc.org/sqlite v1.50.1
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/septagon-oss/pk-shared v0.2.0 // indirect
	github.com/tdewolff/minify/v2 v2.24.13 // indirect
	github.com/tdewolff/parse/v2 v2.8.13 // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	modernc.org/libc v1.72.3 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

retract v0.0.0 // broken: contained local replace directives

// v0.4.0, v0.5.0, and v0.5.1 were withdrawn: their history was rewritten to
// correct commit attribution, so those tags no longer resolve to the content the
// module proxy recorded. v0.6.0 is the same code with clean history.
retract [v0.4.0, v0.5.1]
