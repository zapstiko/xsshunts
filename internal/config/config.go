// Package config parses xsshunts command line options.
package config

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/zapstiko/xsshunts/internal/payloads"
)

// Version is the tool version.
const Version = "1.0.0"

// Options holds every CLI option.
type Options struct {
	URL            string
	File           string
	Stdin          bool
	BrowserKind    string
	BrowserPath    string
	NoBrowser      bool
	Headless       bool
	TimeoutMS      int
	DelayMinMS     int
	DelayMaxMS     int
	Threads        int
	Scan           string
	WordlistFile   string
	MiningOnly     bool
	ParamsSpec     string
	Exclude        string
	Data           string
	Cookie         string
	CookieFile     string
	Headers        []string
	IncludeHeaders string
	ExcludeHeaders string
	Crawl          bool
	Depth          int
	MaxURLs        int
	Output         string
	HTMLReport     string
	PayloadFile    string
	ShowPayloads   bool
	ShowParams     bool
	ShowHeaders    bool
	Silent         bool
	Verbose        bool
	Version        bool
}

// Parse builds Options from the argv slice. It prints help/version and exits
// the process for informational flags.
func Parse(argv []string) *Options {
	o := &Options{}

	flag.StringVar(&o.URL, "u", "", "target URL to scan (e.g. https://example.com/search?q=test)")
	flag.StringVar(&o.URL, "url", "", "target URL to scan")
	flag.StringVar(&o.File, "f", "", "load targets from file (one URL per line)")
	flag.StringVar(&o.File, "file", "", "load targets from file")
	flag.BoolVar(&o.Stdin, "s", false, "silent mode; read targets piped via STDIN")
	flag.BoolVar(&o.Silent, "silent", false, "silent mode")
	flag.StringVar(&o.BrowserKind, "b", "chrome", "browser engine kind (chrome|chromium|edge|brave)")
	flag.StringVar(&o.BrowserKind, "browser", "chrome", "browser engine kind")
	flag.StringVar(&o.BrowserPath, "browser-path", "", "explicit path to the chromium binary")
	flag.BoolVar(&o.NoBrowser, "no-browser", false, "disable browser confirmation (reflection-only mode)")
	flag.BoolVar(&o.Headless, "headless", true, "run the browser headless (true|false)")
	flag.IntVar(&o.TimeoutMS, "timeout", 15000, "page navigation timeout in milliseconds")
	flag.IntVar(&o.DelayMinMS, "delay-min", 3000, "minimum request delay in ms")
	flag.IntVar(&o.DelayMaxMS, "delay-max", 5000, "maximum request delay in ms")
	flag.IntVar(&o.Threads, "t", 1, "number of concurrent scanner workers (1-8)")
	flag.IntVar(&o.Threads, "threads", 1, "number of concurrent scanner workers")
	flag.StringVar(&o.Scan, "scan", "get,post", "modules to test: get,post,path,fragment,header,all")
	flag.StringVar(&o.WordlistFile, "w", "", "custom hidden-parameter wordlist file")
	flag.StringVar(&o.WordlistFile, "wordlist", "", "custom hidden-parameter wordlist file")
	flag.BoolVar(&o.MiningOnly, "m", false, "parameter mining + reflection analysis only (no payload testing)")
	flag.BoolVar(&o.MiningOnly, "mining", false, "parameter mining only")
	flag.StringVar(&o.ParamsSpec, "p", "", "parameters to test (e.g. 'p:js,q:html' or 'a,b')")
	flag.StringVar(&o.ParamsSpec, "param", "", "parameters to test")
	flag.StringVar(&o.Exclude, "e", "", "parameters to skip (comma-separated)")
	flag.StringVar(&o.Exclude, "exclude", "", "parameters to skip")
	flag.StringVar(&o.Data, "d", "", "custom POST data fields (e.g. 'user=admin&search=kw')")
	flag.StringVar(&o.Data, "data", "", "custom POST data fields")
	flag.StringVar(&o.Cookie, "c", "", "cookie string or path to cookie file (e.g. 'session=xyz')")
	flag.StringVar(&o.Cookie, "cookie", "", "cookie string or file")
	flag.StringVar(&o.CookieFile, "cookie-file", "", "load cookies from file (Netscape, JSON, key=value)")
	flag.Var(&headerList{&o.Headers}, "H", "custom HTTP header, repeatable ('Name: value')")
	flag.Var(&headerList{&o.Headers}, "header", "custom HTTP header, repeatable")
	flag.StringVar(&o.IncludeHeaders, "include-header", "", "extra headers to add to header scan (comma-separated)")
	flag.StringVar(&o.ExcludeHeaders, "exclude-header", "", "headers to skip during header scan")
	flag.BoolVar(&o.Crawl, "crawl", false, "crawl the seed URL to discover endpoints")
	flag.IntVar(&o.Depth, "depth", 2, "maximum crawl depth (1-5)")
	flag.IntVar(&o.MaxURLs, "max-urls", 50, "maximum URLs collected while crawling (1-200)")
	flag.StringVar(&o.Output, "o", "", "save JSON report (relative names land in output/)")
	flag.StringVar(&o.Output, "output", "", "save JSON report")
	flag.StringVar(&o.HTMLReport, "html", "", "save HTML report")
	flag.StringVar(&o.PayloadFile, "payload-file", "", "custom payload file (one per line) used for get/post/path/fragment")
	flag.BoolVar(&o.ShowPayloads, "show-payloads", false, "show built-in payloads and exit")
	flag.BoolVar(&o.ShowParams, "show-params", false, "show built-in parameter wordlist and exit")
	flag.BoolVar(&o.ShowHeaders, "show-headers", false, "show built-in target headers and exit")
	flag.BoolVar(&o.Verbose, "v", false, "verbose output")
	flag.BoolVar(&o.Version, "version", false, "print version and exit")
	flag.Usage = usage

	if len(argv) > 0 {
		flag.CommandLine.Parse(argv)
	} else {
		flag.Parse()
	}
	if o.Version {
		fmt.Printf("xsshunts v%s\n", Version)
		os.Exit(0)
	}
	if o.ShowPayloads || o.ShowParams || o.ShowHeaders {
		showKnowledge(o)
		os.Exit(0)
	}
	o.normalize()
	return o
}

type headerList struct{ values *[]string }

func (h headerList) String() string {
	if h.values == nil {
		return ""
	}
	return fmt.Sprint(*h.values)
}

func (h headerList) Set(v string) error {
	if h.values == nil {
		return fmt.Errorf("header value pointer not initialized")
	}
	*h.values = append(*h.values, v)
	return nil
}

func usage() {
	fmt.Fprintf(os.Stderr, "xsshunts v%s - automated multi-vector XSS hunting toolkit (Go)\n\n", Version)
	fmt.Fprintf(os.Stderr, "Usage:\n  xsshunts -u <url> [options]\n  xsshunts -f targets.txt [options]\n  cat urls.txt | xsshunts -s [options]\n")
	fmt.Fprint(os.Stderr, "\nTarget Options:\n  -u, --url URL                    target URL (e.g. https://x.com/page?id=1)\n  -f, --file FILE                  target file, one URL per line\n  -s, --silent                     read targets from STDIN, quiet banner\n\n")
	fmt.Fprint(os.Stderr, "Browser Options:\n  -b, --browser KIND               engine kind: chrome|chromium|edge|brave (default chrome)\n      --browser-path P             explicit chromium binary path\n      --no-browser                 skip browser dialog confirmation (reflection only)\n      --headless true|false        headless browser (default true)\n      --timeout MS                 navigation timeout (default 15000)\n      --delay-min MS / --delay-max MS  request delay range (default 3000-5000)\n  -t, --threads N                  concurrent workers (1-8, default 1)\n\n")
	fmt.Fprint(os.Stderr, "Scan Scope:\n      --scan LIST                  get,post,path,fragment,header or all (default get,post)\n  -w, --wordlist FILE              hidden parameter wordlist\n  -m, --mining                     mining + reflection only\n  -p, --param LIST                 params: 'q' or 'p:js,q:html'\n  -e, --exclude LIST               params to skip\n  -d, --data DATA                  custom POST fields 'user=1&search=x'\n  -c, --cookie C / --cookie-file F session cookies\n  -H, --header 'K: V'              extra request headers (repeatable)\n      --include-header K1,K2       extra headers to attack\n      --exclude-header K           headers to skip\n      --payload-file FILE          custom payload list (one per line)\n\n")
	fmt.Fprint(os.Stderr, "Crawler:\n      --crawl                      discover endpoints automatically\n      --depth N                    crawl depth (default 2)\n      --max-urls N                 URL cap (default 50)\n\n")
	fmt.Fprint(os.Stderr, "Reporting:\n  -o, --output FILE                JSON report (relative => output/)\n      --html FILE                  HTML report\n      --show-payloads / --show-params / --show-headers  inspect builtin data\n  -v, --verbose                    debug output\n      --version                    tool version\n")
}

func (o *Options) normalize() {
	if o.TimeoutMS <= 0 {
		o.TimeoutMS = 15000
	}
	if o.DelayMinMS <= 0 {
		o.DelayMinMS = 1000
	}
	if o.DelayMaxMS < o.DelayMinMS {
		o.DelayMaxMS = o.DelayMinMS
	}
	if o.Threads < 1 {
		o.Threads = 1
	}
	if o.Threads > 8 {
		o.Threads = 8
	}
	if o.Depth < 1 {
		o.Depth = 1
	}
	if o.Depth > 5 {
		o.Depth = 5
	}
	if o.MaxURLs < 1 {
		o.MaxURLs = 50
	}
	if o.MaxURLs > 200 {
		o.MaxURLs = 200
	}
	if o.BrowserKind == "" {
		o.BrowserKind = "chrome"
	}
	if o.Scan == "" {
		o.Scan = "get,post"
	}
}

// ScanSet returns the requested vectors.
func (o *Options) ScanSet() map[string]bool {
	set := map[string]bool{}
	for _, part := range strings.Split(strings.ToLower(o.Scan), ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		switch part {
		case "all":
			set["get"] = true
			set["post"] = true
			set["path"] = true
			set["fragment"] = true
			set["header"] = true
		default:
			set[part] = true
		}
	}
	return set
}

// ExcludedMap parses -e into a name set.
func (o *Options) ExcludedMap() map[string]bool {
	out := map[string]bool{}
	for _, p := range strings.Split(o.Exclude, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out[p] = true
		}
	}
	return out
}

// ForcedContexts parses -p into name->context (value may be empty).
func (o *Options) ForcedContexts() map[string]string {
	out := map[string]string{}
	spec := strings.ReplaceAll(o.ParamsSpec, "&", ",")
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if i := strings.Index(part, ":"); i > 0 {
			out[strings.TrimSpace(strings.ToLower(part[:i]))] = strings.TrimSpace(strings.ToLower(part[i+1:]))
			continue
		}
		if i := strings.Index(part, "="); i > 0 {
			out[strings.TrimSpace(strings.ToLower(part[:i]))] = strings.TrimSpace(strings.ToLower(part[i+1:]))
			continue
		}
		out[part] = ""
	}
	return out
}

// CookieMap resolves cookies from -c (string or file) and --cookie-file.
func (o *Options) CookieMap() map[string]string {
	out := map[string]string{}
	for _, src := range []string{o.CookieFile, o.Cookie} {
		if src == "" {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(src), "{") || strings.HasPrefix(strings.TrimSpace(src), "[") {
			mergeJSONCookies(src, out)
			continue
		}
		if raw, err := os.ReadFile(src); err == nil && len(raw) < 1<<21 {
			parseCookieText(string(raw), out)
			continue
		}
		parseCookieText(src, out)
	}
	return out
}

func parseCookieText(text string, out map[string]string) {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "#HttpOnly_") {
			continue
		}
		line = strings.TrimPrefix(line, "#HttpOnly_")
		if fields := strings.Split(line, "\t"); len(fields) >= 7 && strings.HasPrefix(fields[0], ".") || strings.HasPrefix(line, ".") {
			// Netscape format: domain<TAB>flag<TAB>path<TAB>secure<TAB>expiry<TAB>name<TAB>value
			if len(fields) >= 7 {
				out[fields[5]] = fields[6]
				continue
			}
		}
		if strings.Contains(line, "=") && !strings.Contains(line, " ") {
			parts := strings.SplitN(line, "=", 2)
			out[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			continue
		}
		// "name value" or "name=value; name2=value2"
		for _, chunk := range strings.Split(line, ";") {
			chunk = strings.TrimSpace(chunk)
			if pair := strings.SplitN(chunk, "=", 2); len(pair) == 2 {
				name := strings.Fields(pair[0])
				if len(name) > 0 {
					out[name[len(name)-1]] = strings.TrimSpace(pair[1])
				}
			}
		}
	}
}

func mergeJSONCookies(text string, out map[string]string) {
	var dump interface{}
	if err := json.Unmarshal([]byte(text), &dump); err != nil {
		return
	}
	collectJSON(dump, out)
}

func collectJSON(v interface{}, out map[string]string) {
	switch t := v.(type) {
	case map[string]interface{}:
		name, hasName := t["name"].(string)
		if hasName {
			if val, ok := t["value"].(string); ok && name != "" {
				out[name] = val
				return
			}
		}
		for k, vv := range t {
			if s, ok := vv.(string); ok && k != "" {
				out[k] = s
			}
		}
	case []interface{}:
		for _, item := range t {
			collectJSON(item, out)
		}
	}
}

// BaseHeaders merges -H headers into a map.
func (o *Options) BaseHeaders() map[string]string {
	out := map[string]string{}
	for _, h := range o.Headers {
		if i := strings.Index(h, ":"); i > 0 {
			name := strings.TrimSpace(h[:i])
			val := strings.TrimSpace(h[i+1:])
			out[name] = val
		}
	}
	return out
}

// HeaderScanNames returns the header names attacked by the header vector.
func (o *Options) HeaderScanNames() []string {
	names := []string{"User-Agent", "Referer", "Origin", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-IP", "X-Originating-IP", "X-Client-IP", "X-Requested-With", "Forwarded", "X-Custom-IP-Authorization", "X-WAP-Profile", "Authorization", "X-API-Key"}
	if o.IncludeHeaders != "" {
		for _, h := range strings.Split(o.IncludeHeaders, ",") {
			h = strings.TrimSpace(h)
			if h != "" {
				names = append(names, h)
			}
		}
	}
	excl := map[string]bool{}
	for _, h := range strings.Split(o.ExcludeHeaders, ",") {
		excl[strings.ToLower(strings.TrimSpace(h))] = true
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		if !excl[strings.ToLower(n)] {
			out = append(out, n)
		}
	}
	return out
}

// ValidateTarget checks the URL is absolute.
func ValidateTarget(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("URL must start with http:// or https://")
	}
	if u.Host == "" {
		return nil, fmt.Errorf("URL has no host")
	}
	return u, nil
}

func showKnowledge(o *Options) {
	switch {
	case o.ShowPayloads:
		fmt.Println("# built-in payloads ({TOKEN} is replaced by the alert canary)")
		for _, ctx := range []string{"html", "attribute", "javascript", "url"} {
			fmt.Printf("## context: %s\n", ctx)
			for _, p := range payloads.ByContext(ctx) {
				fmt.Printf("  %s\n", p)
			}
		}
	case o.ShowParams:
		for _, p := range payloads.KnownParams() {
			fmt.Println(p)
		}
	case o.ShowHeaders:
		fmt.Println("User-Agent\nReferer\nOrigin\nX-Forwarded-For\nX-Forwarded-Host\nX-Forwarded-Proto\nX-Real-IP\nX-Originating-IP\nX-Client-IP\nX-Requested-With\nForwarded\nX-Custom-IP-Authorization\nX-WAP-Profile\nAuthorization\nX-API-Key")
	}
}
