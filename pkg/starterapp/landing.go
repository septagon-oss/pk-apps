// Package starterapp — landing.go renders the public product-and-status
// landing page without exposing seed credentials or operator-only data.
//
// Implements: REQ-016.
// Per: ADR-0017.
// Discipline: C-14.
package starterapp

import (
	"html/template"
	"net/http"
)

type landingView struct {
	AppName       string
	AppVersion    string
	Environment   string
	AdminBasePath string
	Modules       []string
}

var landingTemplate = template.Must(template.New("landing").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <title>{{.AppName}} · PlatformKit OSS</title>
  <style>
    :root {
      --ink: #15221f;
      --muted: #62706b;
      --paper: #f2efe7;
      --sheet: #fffdf7;
      --field: #12201d;
      --line: #d2cec2;
      --signal: #d8f35d;
      --accent: #0f5d4e;
      --display: "Iowan Old Style", "Palatino Linotype", Palatino, Georgia, serif;
      --body: "IBM Plex Sans", Aptos, "Helvetica Neue", sans-serif;
      --mono: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
    }
    * { box-sizing: border-box; }
    html { min-width: 320px; background: var(--paper); scroll-behavior: smooth; }
    body { margin: 0; color: var(--ink); background: var(--paper); font: 15px/1.55 var(--body); }
    a { color: inherit; text-underline-offset: 3px; }
    :focus-visible { outline: 3px solid #326de6; outline-offset: 3px; }
    .skip { position: fixed; z-index: 10; inset: 8px auto auto 8px; padding: 10px 14px; color: white; background: var(--accent); transform: translateY(-160%); }
    .skip:focus { transform: translateY(0); }
    header {
      min-height: 72px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 24px;
      padding: 14px clamp(18px, 5vw, 70px);
      color: #eff4e9;
      background: var(--field);
      border-bottom: 1px solid rgba(255,255,255,.14);
    }
    .brand { display: inline-flex; align-items: center; gap: 12px; font-weight: 780; letter-spacing: .035em; }
    .mark { width: 31px; height: 31px; display: grid; grid-template-columns: repeat(2,1fr); gap: 3px; padding: 5px; border: 1px solid rgba(255,255,255,.42); }
    .mark i { display: block; background: var(--signal); }
    .mark i:nth-child(2) { background: transparent; border: 1px solid rgba(255,255,255,.5); }
    .mark i:nth-child(3) { grid-column: 1 / -1; height: 4px; align-self: end; }
    .runtime { display: flex; align-items: center; gap: 9px; color: #aebbb2; font: 10px/1.3 var(--mono); letter-spacing: .08em; text-transform: uppercase; }
    .runtime i { width: 8px; height: 8px; border-radius: 50%; background: var(--signal); box-shadow: 0 0 0 4px rgba(216,243,93,.12); }
    main { overflow: hidden; }
    .hero {
      min-height: min(720px, calc(100vh - 72px));
      display: grid;
      grid-template-columns: minmax(0, 1.35fr) minmax(270px, .65fr);
      border-bottom: 1px solid var(--line);
    }
    .hero-copy {
      display: flex;
      flex-direction: column;
      justify-content: center;
      padding: clamp(60px, 10vw, 144px) clamp(22px, 7vw, 100px);
      border-right: 1px solid var(--line);
    }
    .eyebrow { margin: 0 0 24px; color: var(--accent); font: 750 11px/1.3 var(--mono); letter-spacing: .15em; text-transform: uppercase; }
    h1 { max-width: 11ch; margin: 0; font: 500 clamp(58px, 9vw, 128px)/.86 var(--display); letter-spacing: -.055em; }
    .lede { max-width: 49ch; margin: 32px 0 0; color: var(--muted); font-size: clamp(17px, 2vw, 21px); }
    .actions { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 38px; }
    .button { min-height: 48px; display: inline-flex; align-items: center; justify-content: center; padding: 0 18px; border: 1px solid var(--ink); font-weight: 780; text-decoration: none; }
    .button.primary { color: var(--field); background: var(--signal); border-color: #aabe45; }
    .button.secondary { background: transparent; }
    .button:hover { transform: translateY(-1px); }
    .manifest { display: flex; flex-direction: column; justify-content: flex-end; padding: clamp(28px, 5vw, 68px); background: var(--sheet); }
    .manifest > p { margin: 0 0 16px; color: var(--muted); font: 10px/1.3 var(--mono); letter-spacing: .12em; text-transform: uppercase; }
    .module-count { margin: 0; font: 500 clamp(72px, 10vw, 142px)/.8 var(--display); letter-spacing: -.06em; }
    .manifest h2 { margin: 20px 0 8px; font: 500 30px/1.05 var(--display); }
    .manifest > span { color: var(--muted); font-size: 13px; }
    .routes { display: grid; grid-template-columns: repeat(3,1fr); border-bottom: 1px solid var(--line); }
    .route { min-height: 230px; padding: clamp(26px, 5vw, 60px); border-right: 1px solid var(--line); }
    .route:last-child { border-right: 0; }
    .route span { color: var(--accent); font: 700 10px/1.3 var(--mono); letter-spacing: .12em; text-transform: uppercase; }
    .route h2 { margin: 38px 0 10px; font: 500 clamp(27px, 3vw, 38px)/1 var(--display); letter-spacing: -.025em; }
    .route p { max-width: 35ch; margin: 0; color: var(--muted); }
    .route a { min-height: 44px; display: inline-flex; align-items: center; margin-top: 22px; color: var(--accent); font-weight: 750; }
    .modules { display: grid; grid-template-columns: minmax(250px,.6fr) minmax(0,1.4fr); gap: clamp(30px,7vw,100px); padding: clamp(64px,10vw,140px) clamp(22px,7vw,100px); background: var(--field); color: #eff4e9; }
    .modules .eyebrow { color: var(--signal); }
    .modules h2 { max-width: 8ch; margin: 0; font: 500 clamp(46px,6vw,80px)/.92 var(--display); letter-spacing: -.045em; }
    .module-list { display: grid; grid-template-columns: repeat(2,minmax(0,1fr)); align-content: start; border-top: 1px solid rgba(255,255,255,.2); }
    .module-list div { min-width: 0; padding: 16px 10px 16px 0; border-bottom: 1px solid rgba(255,255,255,.14); color: #b8c3bc; font: 12px/1.35 var(--mono); overflow-wrap: anywhere; }
    footer { display: flex; justify-content: space-between; gap: 20px; padding: 24px clamp(22px,5vw,70px); color: var(--muted); background: var(--paper); font: 10px/1.4 var(--mono); letter-spacing: .08em; text-transform: uppercase; }
    @media (max-width: 850px) {
      .hero { min-height: 0; grid-template-columns: 1fr; }
      .hero-copy { min-height: 600px; border-right: 0; border-bottom: 1px solid var(--line); }
      .manifest { min-height: 300px; }
      .routes { grid-template-columns: 1fr; }
      .route { min-height: 0; border-right: 0; border-bottom: 1px solid var(--line); }
      .route:last-child { border-bottom: 0; }
      .modules { grid-template-columns: 1fr; }
    }
    @media (max-width: 520px) {
      header { align-items: flex-start; }
      .runtime { max-width: 120px; justify-content: flex-end; text-align: right; }
      .hero-copy { min-height: 520px; }
      h1 { font-size: clamp(52px,19vw,78px); }
      .actions { flex-direction: column; }
      .button { width: 100%; }
      .module-list { grid-template-columns: 1fr; }
      footer { flex-direction: column; }
    }
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after { scroll-behavior: auto !important; transition: none !important; }
    }
  </style>
</head>
<body>
  <a class="skip" href="#main">Skip to content</a>
  <header>
    <div class="brand"><span class="mark" aria-hidden="true"><i></i><i></i><i></i></span><span>PLATFORMKIT / OSS</span></div>
    <div class="runtime"><i aria-hidden="true"></i><span>{{.Environment}} · {{.AppVersion}}</span></div>
  </header>
  <main id="main">
    <section class="hero" aria-labelledby="hero-title">
      <div class="hero-copy">
        <p class="eyebrow">The runnable foundation</p>
        <h1 id="hero-title">One process. Real product surface.</h1>
        <p class="lede">A local-first SaaS core with tenant isolation, identity, audit, content, notifications, health, and a working operator console already composed.</p>
        <div class="actions">
          <a class="button primary" href="{{.AdminBasePath}}">Open operator workspace</a>
          <a class="button secondary" href="/ready">Inspect readiness</a>
        </div>
      </div>
      <aside class="manifest" aria-label="Composition summary">
        <p>Runtime manifest</p>
        <strong class="module-count">{{len .Modules}}</strong>
        <h2>modules composed</h2>
        <span>One SQLite pool · one catalog · one HTTP perimeter</span>
      </aside>
    </section>
    <section class="routes" aria-label="Runtime entry points">
      <article class="route"><span>01 / operate</span><h2>Admin</h2><p>Manage declared resources through the scope-aware operator workspace.</p><a href="{{.AdminBasePath}}">Open console →</a></article>
      <article class="route"><span>02 / observe</span><h2>Health</h2><p>Check module health and runtime readiness without exposing process internals.</p><a href="/healthz">View health →</a></article>
      <article class="route"><span>03 / discover</span><h2>OpenAPI</h2><p>Inspect the machine-readable operations contributed by installed modules.</p><a href="/openapi/extensions.json">View extension spec →</a></article>
    </section>
    <section class="modules" aria-labelledby="modules-title">
      <div><p class="eyebrow">Composition, made visible</p><h2 id="modules-title">What is running.</h2></div>
      <div class="module-list">{{range .Modules}}<div>{{.}}</div>{{end}}</div>
    </section>
  </main>
  <footer><span>{{.AppName}}</span><span>PlatformKit OSS · built to be extended</span></footer>
</body>
</html>`))

func (a *App) indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_ = landingTemplate.Execute(w, landingView{
		AppName:       a.appName,
		AppVersion:    a.appVersion,
		Environment:   a.environment,
		AdminBasePath: a.adminBasePath,
		Modules:       a.AllModuleIDs(),
	})
}
