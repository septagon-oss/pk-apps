// Implements: REQ-016.
// Per: ADR-0017.
// Discipline: C-14.

package pollmodule

import (
	"html/template"
	"net/http"
	"time"
)

type publicOptionView struct {
	Index    int
	Label    string
	Count    int
	Percent  int
	Selected bool
}

type publicPageView struct {
	Poll        PublicPoll
	Options     []publicOptionView
	Total       int
	Accepting   bool
	Voted       bool
	Error       string
	ClosesLabel string
}

var publicPollTemplate = template.Must(template.New("public-poll").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <title>{{.Poll.Title}} · PlatformKit Polls</title>
  <style>
    :root{--ink:#15221f;--muted:#61706a;--paper:#f2efe7;--sheet:#fffdf7;--field:#12201d;--line:#d2cec2;--signal:#d8f35d;--accent:#0f5d4e;--danger:#a33131;--display:"Iowan Old Style","Palatino Linotype",Palatino,Georgia,serif;--body:"IBM Plex Sans",Aptos,"Helvetica Neue",sans-serif;--mono:"IBM Plex Mono","SFMono-Regular",Consolas,monospace}
    *{box-sizing:border-box}html{min-width:320px;background:var(--paper)}body{min-height:100vh;margin:0;color:var(--ink);background:var(--paper);font:15px/1.55 var(--body)}:focus-visible{outline:3px solid #326de6;outline-offset:3px}
    header{min-height:68px;display:flex;align-items:center;justify-content:space-between;gap:18px;padding:13px clamp(18px,5vw,64px);color:#eff4e9;background:var(--field);border-bottom:1px solid rgba(255,255,255,.14)}
    .brand{display:inline-flex;align-items:center;gap:11px;font-size:12px;font-weight:800;letter-spacing:.06em}.mark{width:29px;height:29px;display:grid;grid-template-columns:repeat(2,1fr);gap:3px;padding:5px;border:1px solid rgba(255,255,255,.42)}.mark i{display:block;background:var(--signal)}.mark i:nth-child(2){background:transparent;border:1px solid rgba(255,255,255,.5)}.mark i:nth-child(3){grid-column:1/-1;height:3px;align-self:end}
    .status{display:inline-flex;align-items:center;gap:8px;color:#b9c4bd;font:10px/1.2 var(--mono);letter-spacing:.1em;text-transform:uppercase}.status i{width:8px;height:8px;border-radius:50%;background:var(--signal)}
    main{width:min(100%,1120px);margin:auto;padding:clamp(44px,8vw,110px) clamp(18px,5vw,64px)}
    .layout{display:grid;grid-template-columns:minmax(0,1.25fr) minmax(290px,.75fr);gap:clamp(40px,8vw,100px);align-items:start}.eyebrow{margin:0 0 21px;color:var(--accent);font:750 10px/1.3 var(--mono);letter-spacing:.15em;text-transform:uppercase}h1{max-width:12ch;margin:0;font:500 clamp(48px,7vw,88px)/.92 var(--display);letter-spacing:-.045em;overflow-wrap:anywhere}.description{max-width:54ch;margin:27px 0 0;color:var(--muted);font-size:clamp(16px,2vw,19px);white-space:pre-wrap}
    .meta{display:flex;flex-wrap:wrap;gap:9px 22px;margin-top:32px;padding-top:18px;border-top:1px solid var(--line);color:var(--muted);font:10px/1.4 var(--mono);letter-spacing:.08em;text-transform:uppercase}
    .panel{padding:clamp(22px,4vw,38px);background:var(--sheet);border:1px solid var(--line)}.panel h2{margin:0;font:500 31px/1 var(--display);letter-spacing:-.02em}.panel-copy{margin:9px 0 22px;color:var(--muted);font-size:13px}
    fieldset{min-width:0;margin:0;padding:0;border:0}legend{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0,0,0,0)}.choice{position:relative;display:block;margin-top:10px}.choice input{position:absolute;z-index:1;inset:0;width:100%;height:100%;margin:0;opacity:0;cursor:pointer}.choice span{min-height:54px;display:flex;align-items:center;gap:12px;padding:12px 14px;background:var(--paper);border:1px solid #aaa89f;cursor:pointer;pointer-events:none}.choice span::before{content:"";width:17px;height:17px;flex:0 0 17px;border:1px solid #70756f;border-radius:50%;box-shadow:inset 0 0 0 4px var(--paper)}.choice input:checked+span{border-color:var(--accent);background:#edf4e9}.choice input:checked+span::before{background:var(--accent)}.choice input:focus-visible+span{outline:3px solid #326de6;outline-offset:2px}
    button{width:100%;min-height:50px;margin-top:18px;padding:10px 16px;color:var(--field);background:var(--signal);border:1px solid #aabe45;font:800 14px/1.2 var(--body);cursor:pointer}button:hover{background:#e5fa82}.trap{position:absolute!important;width:1px!important;height:1px!important;overflow:hidden!important;clip:rect(0,0,0,0)!important}
    .notice{margin:0 0 18px;padding:12px 14px;border-left:4px solid var(--accent);background:#edf4e9;font-size:13px}.notice.error{border-color:var(--danger);color:#672121;background:#fff1ee}
    .results{margin-top:30px;padding-top:25px;border-top:1px solid var(--line)}.result{margin-top:17px}.result-head{display:flex;justify-content:space-between;gap:15px;margin-bottom:7px;font-size:12px}.result-head strong{font-weight:750}.result-head span{color:var(--muted);font-family:var(--mono);font-size:10px}progress{width:100%;height:7px;display:block;appearance:none;border:0;background:#dfe1d7}progress::-webkit-progress-bar{background:#dfe1d7}progress::-webkit-progress-value{background:var(--accent)}progress::-moz-progress-bar{background:var(--accent)}.result.selected strong::after{content:" · your vote";color:var(--accent);font:700 9px/1 var(--mono);letter-spacing:.06em;text-transform:uppercase}
    footer{margin-top:60px;padding-top:18px;border-top:1px solid var(--line);display:flex;justify-content:space-between;gap:20px;color:var(--muted);font:10px/1.4 var(--mono);letter-spacing:.07em;text-transform:uppercase}
    @media(max-width:760px){main{padding-top:54px}.layout{grid-template-columns:1fr}.panel{padding:22px}footer{flex-direction:column}}@media(max-width:420px){header{align-items:flex-start}.status{max-width:110px;text-align:right}h1{font-size:49px}}
    @media(prefers-reduced-motion:reduce){*,*::before,*::after{scroll-behavior:auto!important;transition:none!important}}
  </style>
</head>
<body>
  <header><div class="brand"><span class="mark" aria-hidden="true"><i></i><i></i><i></i></span><span>PLATFORMKIT / POLLS</span></div><div class="status"><i aria-hidden="true"></i><span>{{.Poll.Status}}</span></div></header>
  <main>
    <div class="layout">
      <section aria-labelledby="poll-title"><p class="eyebrow">Public decision room</p><h1 id="poll-title">{{.Poll.Title}}</h1>{{if .Poll.Description}}<p class="description">{{.Poll.Description}}</p>{{end}}<div class="meta"><span>{{.Total}} recorded {{if eq .Total 1}}vote{{else}}votes{{end}}</span>{{if .ClosesLabel}}<span>{{.ClosesLabel}}</span>{{end}}</div></section>
      <section class="panel" aria-labelledby="ballot-title">
        <h2 id="ballot-title">{{if .Accepting}}Cast your vote{{else}}Final results{{end}}</h2>
        <p class="panel-copy">{{if .Accepting}}Choose one option. Returning from this browser updates your ballot.{{else}}Voting is closed; the results remain visible.{{end}}</p>
        {{if .Voted}}<div class="notice" role="status">Your ballot was recorded. You can change it while voting stays open.</div>{{end}}
        {{if .Error}}<div class="notice error" role="alert">{{.Error}}</div>{{end}}
        {{if .Accepting}}
        <form method="post" action="/polls/{{.Poll.Slug}}/vote">
          <fieldset><legend>Choose one option</legend>{{range .Options}}<label class="choice"><input type="radio" name="option_index" value="{{.Index}}" {{if .Selected}}checked{{end}} required><span>{{.Label}}</span></label>{{end}}</fieldset>
          <label class="trap" aria-hidden="true">Company<input name="company" tabindex="-1" autocomplete="off"></label>
          <button type="submit">Record this choice</button>
        </form>
        {{end}}
        <div class="results" aria-label="Current results">{{range .Options}}<div class="result {{if .Selected}}selected{{end}}"><div class="result-head"><strong>{{.Label}}</strong><span>{{.Count}} · {{.Percent}}%</span></div><progress value="{{.Count}}" max="{{if $.Total}}{{$.Total}}{{else}}1{{end}}">{{.Percent}}%</progress></div>{{end}}</div>
      </section>
    </div>
    <footer><span>Anonymous ballot IDs are signed</span><span>One current choice per browser</span></footer>
  </main>
</body>
</html>`))

var publicUnavailableTemplate = template.Must(template.New("public-unavailable").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{.Title}} · PlatformKit Polls</title>
<style>*{box-sizing:border-box}body{min-height:100vh;margin:0;display:grid;place-items:center;padding:24px;color:#eff4e9;background:#12201d;font-family:"IBM Plex Sans",Aptos,sans-serif}main{width:min(100%,660px);padding:clamp(30px,8vw,70px);border:1px solid rgba(255,255,255,.22)}small{color:#d8f35d;font:700 11px/1.3 "IBM Plex Mono",monospace;letter-spacing:.14em;text-transform:uppercase}h1{max-width:9ch;margin:20px 0;font:500 clamp(46px,10vw,82px)/.92 "Iowan Old Style",Georgia,serif;letter-spacing:-.045em}p{max-width:48ch;color:#b8c3bc;line-height:1.65}a{min-height:44px;display:inline-flex;align-items:center;margin-top:16px;padding:0 16px;color:#12201d;background:#d8f35d;font-weight:800;text-decoration:none}:focus-visible{outline:3px solid #8ab4ff;outline-offset:4px}</style>
</head><body><main><small>{{.Status}} / public polls</small><h1>{{.Title}}</h1><p>{{.Message}}</p><a href="/">Return to PlatformKit</a></main></body></html>`))

func writePublicPage(w http.ResponseWriter, status int, view publicPageView) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set(
		"Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
	)
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = publicPollTemplate.Execute(w, view)
}

func writePublicUnavailable(w http.ResponseWriter, status int, title, message string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set(
		"Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
	)
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = publicUnavailableTemplate.Execute(w, map[string]any{
		"Status":  status,
		"Title":   title,
		"Message": message,
	})
}

func buildPublicPageView(
	poll *Poll,
	counts map[int]int,
	currentChoice int,
	hasChoice bool,
	now time.Time,
) publicPageView {
	total := sumCounts(counts)
	options := make([]publicOptionView, len(poll.Options))
	for index, label := range poll.Options {
		percent := 0
		if total > 0 {
			percent = counts[index] * 100 / total
		}
		options[index] = publicOptionView{
			Index:    index,
			Label:    label,
			Count:    counts[index],
			Percent:  percent,
			Selected: hasChoice && currentChoice == index,
		}
	}
	closesLabel := ""
	if poll.ClosesAt != nil {
		if poll.acceptsVotes(now) {
			closesLabel = "Closes " + poll.ClosesAt.UTC().Format("2 Jan 2006 · 15:04 UTC")
		} else {
			closesLabel = "Closed " + poll.ClosesAt.UTC().Format("2 Jan 2006 · 15:04 UTC")
		}
	}
	return publicPageView{
		Poll:        publicPoll(poll, now),
		Options:     options,
		Total:       total,
		Accepting:   poll.acceptsVotes(now),
		ClosesLabel: closesLabel,
	}
}
