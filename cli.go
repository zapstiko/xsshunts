package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/zapstiko/xsshunts/appmeta"
	"github.com/zapstiko/xsshunts/browser"
	"github.com/zapstiko/xsshunts/config"
	"github.com/zapstiko/xsshunts/crawler"
	"github.com/zapstiko/xsshunts/detection"
	"github.com/zapstiko/xsshunts/logger"
	"github.com/zapstiko/xsshunts/models"
	"github.com/zapstiko/xsshunts/parsers"
	"github.com/zapstiko/xsshunts/payloads"
	"github.com/zapstiko/xsshunts/reporter"
	"github.com/zapstiko/xsshunts/scanner"
	"github.com/zapstiko/xsshunts/updater"
	"github.com/zapstiko/xsshunts/utils"
	"github.com/zapstiko/xsshunts/wordlists"
)

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

type cliOptions struct {
	URL             string
	File            string
	Browser         string
	Channel         string
	Headless        string
	Timeout         int
	DelayMin        int
	DelayMax        int
	Threads         int
	Scan            string
	Wordlist        string
	Mining          bool
	Params          stringList
	Exclude         string
	Data            string
	Cookie          string
	CookieFile      string
	Headers         stringList
	Context         string
	IncludeHeaders  stringList
	ExcludeHeaders  stringList
	Crawl           bool
	Depth           int
	MaxURLs         int
	ShowPayloads    bool
	ShowParams      bool
	ShowHeaders     bool
	Output          string
	Silent          bool
	Verbose         bool
	Help            bool
	Version         bool
	Update          bool
	InstallBrowsers bool
}

func buildFlagSet() (*flag.FlagSet, *cliOptions) {
	o := &cliOptions{}
	fs := flag.NewFlagSet("xsshunts", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	fs.StringVar(&o.URL, "u", "", "target URL")
	fs.StringVar(&o.URL, "url", "", "target URL")

	fs.StringVar(&o.File, "f", "", "targets file")
	fs.StringVar(&o.File, "file", "", "targets file")
	fs.StringVar(&o.File, "l", "", "targets file (alias)")
	fs.StringVar(&o.File, "list", "", "targets file (alias)")

	fs.StringVar(&o.Browser, "b", "firefox", "browser engine")
	fs.StringVar(&o.Browser, "browser", "firefox", "browser engine")
	fs.StringVar(&o.Channel, "channel", "", "browser channel (chrome|msedge)")
	fs.StringVar(&o.Headless, "headless", "true", "headless true|false")
	fs.IntVar(&o.Timeout, "timeout", 15000, "navigation timeout ms")
	fs.IntVar(&o.DelayMin, "delay-min", 3000, "minimum delay ms")
	fs.IntVar(&o.DelayMax, "delay-max", 5000, "maximum delay ms")

	fs.IntVar(&o.Threads, "t", 1, "concurrency")
	fs.IntVar(&o.Threads, "threads", 1, "concurrency")
	fs.IntVar(&o.Threads, "concurrency", 1, "concurrency")

	fs.StringVar(&o.Scan, "scan", "get,post", "scan modules")
	fs.StringVar(&o.Wordlist, "w", "", "wordlist file")
	fs.StringVar(&o.Wordlist, "wordlist", "", "wordlist file")

	fs.BoolVar(&o.Mining, "m", false, "mining only")
	fs.BoolVar(&o.Mining, "mining", false, "mining only")
	fs.BoolVar(&o.Mining, "parameter-mining", false, "mining only")
	fs.BoolVar(&o.Mining, "mine", false, "mining only")

	fs.Var(&o.Params, "p", "parameters to test")
	fs.Var(&o.Params, "param", "parameters to test")
	fs.Var(&o.Params, "params", "parameters to test")

	fs.StringVar(&o.Exclude, "e", "", "exclude parameters")
	fs.StringVar(&o.Exclude, "exclude", "", "exclude parameters")

	fs.StringVar(&o.Data, "d", "", "POST data")
	fs.StringVar(&o.Data, "data", "", "POST data")
	fs.StringVar(&o.Data, "postfields", "", "POST data")

	fs.StringVar(&o.Cookie, "c", "", "cookie string or file")
	fs.StringVar(&o.Cookie, "cookie", "", "cookie string or file")
	fs.StringVar(&o.Cookie, "cookies", "", "cookie string or file")
	fs.StringVar(&o.CookieFile, "cookie-file", "", "cookie file")
	fs.StringVar(&o.CookieFile, "cookie-jar", "", "cookie file")

	fs.Var(&o.Headers, "H", "custom header")
	fs.Var(&o.Headers, "header", "custom header")
	fs.Var(&o.Headers, "headers", "custom header")

	fs.StringVar(&o.Context, "context", "", "default injection context")

	fs.Var(&o.IncludeHeaders, "include-header", "extra header scan targets")
	fs.Var(&o.IncludeHeaders, "include-headers", "extra header scan targets")
	fs.Var(&o.ExcludeHeaders, "exclude-header", "header scan skips")
	fs.Var(&o.ExcludeHeaders, "exclude-headers", "header scan skips")

	fs.BoolVar(&o.Crawl, "crawl", false, "enable crawler")
	fs.IntVar(&o.Depth, "depth", 2, "crawl depth")
	fs.IntVar(&o.MaxURLs, "max-urls", 50, "crawl max urls")

	fs.BoolVar(&o.ShowPayloads, "show-payloads", false, "show built-in payloads")
	fs.BoolVar(&o.ShowParams, "show-params", false, "show built-in params")
	fs.BoolVar(&o.ShowParams, "show-parameters", false, "show built-in params")
	fs.BoolVar(&o.ShowHeaders, "show-headers", false, "show built-in headers")

	fs.StringVar(&o.Output, "o", "", "JSON report path")
	fs.StringVar(&o.Output, "output", "", "JSON report path")

	fs.BoolVar(&o.Silent, "s", false, "silent mode")
	fs.BoolVar(&o.Silent, "silent", false, "silent mode")
	fs.BoolVar(&o.Silent, "q", false, "silent mode")
	fs.BoolVar(&o.Silent, "quiet", false, "silent mode")

	fs.BoolVar(&o.Verbose, "v", false, "verbose mode")
	fs.BoolVar(&o.Verbose, "verbose", false, "verbose mode")

	fs.BoolVar(&o.Help, "h", false, "show help")
	fs.BoolVar(&o.Help, "help", false, "show help")

	fs.BoolVar(&o.Version, "version", false, "show version")
	fs.BoolVar(&o.Update, "update", false, "update to the latest release")

	fs.BoolVar(&o.InstallBrowsers, "install-browsers", false, "install Playwright browsers and exit")

	return fs, o
}

func printHelp() {
	fmt.Print(`
XSSHuntS - An Automatic Multi-Vector XSS Scanner (Go + Playwright)

Usage:
  xsshunts -u <url> [options]
  xsshunts -f targets.txt [options]
  cat targets.txt | xsshunts -s [options]

Target Options:
  -u, --url URL                 Target URL to scan (e.g. https://example.com/search?q=test)
  -f, --file FILE               Load targets from file (one URL per line)

Browser & Engine Options:
  -b, --browser ENGINE          Browser engine: firefox, chromium, webkit (default: firefox)
  --channel NAME                Use an installed browser channel (chrome, msedge)
  --headless true|false         Run browser in headless mode (default: true)
  --timeout MS                  Page navigation timeout in milliseconds (default: 15000)
  --delay-min MS                Minimum request delay in ms (default: 3000)
  --delay-max MS                Maximum request delay in ms (default: 5000)
  -t, --threads, --concurrency  Number of concurrent browser tabs/workers (1-5, default: 1)

Scan Scope Options:
  --scan MODULES                Modules: get, post, path, fragment, header, all (default: get,post)
  -w, --wordlist FILE           Custom parameter wordlist file to probe
  -m, --mining                  Perform parameter mining and reflection analysis only
  -p, --param PARAMS            Parameters to test (e.g. 'p:js,q:html' or 'name')
  -e, --exclude PARAMS          Parameters to skip during testing (comma-separated)
  -d, --data POSTFIELDS         Custom POST data fields (e.g. 'username=admin&search=keyword')
  -c, --cookie COOKIE           Cookie string or path to cookie file (e.g. 'session=xyz')
  --cookie-file FILE            Load cookies from file (Netscape, JSON, or key=value)
  -H, --header HEADER           Custom HTTP header (repeatable, e.g. 'Authorization: Bearer token')
  --context CONTEXT             Default injection context: js, html, attr, url, dom
  --include-header HEADERS      Headers to add to header scan (comma-separated)
  --exclude-header HEADERS      Headers to skip during header scan (comma-separated)

Crawler / Spider Options:
  --crawl                       Enable internal spider to discover endpoints automatically
  --depth DEPTH                 Maximum crawl depth (1-5, default: 2)
  --max-urls N                  Maximum total URLs collected (1-200, default: 50)

Information Options:
  --show-payloads               Show all built-in XSS payloads and exit
  --show-params                 Show all built-in known parameters and exit
  --show-headers                Show all built-in target HTTP headers and exit

Update Options:
  --update                      Update xsshunts to the latest GitHub release and exit

Output & Reporting Options:
  -o, --output FILE             Save report JSON (saved to output/ unless absolute path given)
  -s, --silent                  Silent mode (suppress banners and progress, output only findings)
  -v, --verbose                 Enable verbose debugging output
  -h, --help                    Show this help message and exit
  --version                     Show program's version number and exit
  --install-browsers            Download Playwright browser engines and exit

Legal: use only against systems you are authorized to test.
`)
}

// run is the process entry point; returns an exit code.
func run() int {
	if os.Getenv("PLAYWRIGHT_DOWNLOAD_HOST") == "" {
		os.Setenv("PLAYWRIGHT_DOWNLOAD_HOST", "https://cdn.playwright.dev/dbazure/download/playwright")
	}

	fs, opts := buildFlagSet()
	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%sxsshunts: error: %s%s\n", "", err.Error(), "")
		fmt.Fprintln(os.Stderr, "(use 'xsshunts -h' or 'xsshunts --help' to view all available options)")
		return 2
	}

	if opts.Help {
		lg := logger.NewLogger(opts.Verbose, false)
		lg.PrintBanner()
		printHelp()
		return 0
	}

	if opts.Version {
		fmt.Printf("XSSHuntS/xsshunts %s\n", appmeta.Version)
		return 0
	}

	if opts.Update {
		return runUpdate()
	}

	if opts.Channel != "" {
		os.Setenv("XSSHUNTS_CHANNEL", opts.Channel)
	}

	if opts.InstallBrowsers {
		fmt.Println("[*] installing Playwright runtime and browser engines...")
		if err := browser.InstallBrowsers("firefox", "chromium", "webkit"); err == nil {
			fmt.Println("[+] browser engines installed")
			return 0
		} else {
			fmt.Printf("[!] browser engine download failed: %v\n", err)
		}

		fmt.Println("[*] trying the npm driver fallback...")
		driverDir, err := browser.EnsureRuntime()
		if err != nil {
			fmt.Fprintf(os.Stderr, "xsshunts: error: could not set up the Playwright runtime: %v\n", err)
			return 1
		}
		if chrome := browser.SystemChromePath(); chrome != "" {
			if driverDir != "" {
				fmt.Println("[+] Playwright driver is ready (bootstrapped from the npm registry).")
			} else {
				fmt.Println("[+] Playwright driver is ready.")
			}
			fmt.Printf("[+] Found installed browser: %s\n", chrome)
			fmt.Println("[+] xsshunts will use it automatically when a Playwright engine is unavailable.")
			return 0
		}
		fmt.Fprintln(os.Stderr, "xsshunts: error: browser downloads are blocked and no installed Chrome/Edge/Chromium was found.")
		fmt.Fprintln(os.Stderr, "Install Google Chrome (or set XSSHUNTS_BROWSER_PATH) and run --install-browsers again.")
		return 1
	}

	if handleShowOptions(opts) {
		return 0
	}

	if opts.Browser != "firefox" && opts.Browser != "chromium" && opts.Browser != "webkit" {
		fmt.Fprintf(os.Stderr, "xsshunts: error: argument --browser: invalid choice: '%s' (choose from 'firefox', 'chromium', 'webkit')\n", opts.Browser)
		return 2
	}
	headlessLower := strings.ToLower(strings.TrimSpace(opts.Headless))
	if headlessLower != "true" && headlessLower != "false" {
		fmt.Fprintf(os.Stderr, "xsshunts: error: argument --headless: invalid choice: '%s' (choose from 'true', 'false')\n", opts.Headless)
		return 2
	}
	isHeadless := headlessLower == "true"

	log := logger.NewLogger(opts.Verbose, opts.Silent)
	log.PrintBanner()

	rawTargets := loadTargetURLs(opts)
	if len(rawTargets) == 0 {
		fmt.Fprintf(os.Stderr, "xsshunts: error: target URL is required via -u/--url, -f/--file, or standard input pipe\n")
		fmt.Fprintln(os.Stderr, "(use 'xsshunts -h' or 'xsshunts --help' to view all available options)")
		return 2
	}

	var validTargets []string
	for _, raw := range rawTargets {
		norm, ok := normalizeTargetURL(raw)
		if ok {
			validTargets = append(validTargets, norm)
		} else if !opts.Silent {
			log.Warning(fmt.Sprintf("skipping invalid URL: '%s'", raw))
		}
	}
	if len(validTargets) == 0 {
		if !opts.Silent {
			log.Error("no valid target URLs found to scan")
		}
		return 1
	}

	customHeaders := parseCustomHeaders(opts.Headers)
	var customPostfields map[string]string
	if strings.TrimSpace(opts.Data) != "" {
		customPostfields = parsers.ParsePostfieldsString(opts.Data)
	}

	scanModules := parseScanModules(opts.Scan)
	targetParams, targetParamContexts := parseTargetParams(opts.Params)
	defaultContext := detection.NormalizeContextName(opts.Context)
	excludeParams := parseExcludeParams(opts.Exclude)
	includeHeaders := parseHeaderList(opts.IncludeHeaders)
	excludeHeaders := parseHeaderList(opts.ExcludeHeaders)

	exePath, err := os.Executable()
	baseDir := "."
	if err == nil {
		baseDir = filepath.Dir(exePath)
	}

	var resolvedOutput string
	if strings.TrimSpace(opts.Output) != "" {
		resolvedOutput = resolveOutputPath(opts.Output, baseDir)
	}

	var resolvedWordlist string
	var wordlistParams []string
	if strings.TrimSpace(opts.Wordlist) != "" {
		wlPath, ok := resolveWordlistPath(opts.Wordlist, baseDir)
		if !ok {
			log.Error(fmt.Sprintf("wordlist file not found: '%s'", opts.Wordlist))
			return 1
		}
		content, err := os.ReadFile(wlPath)
		if err != nil {
			log.Error(fmt.Sprintf("wordlist file not found: '%s'", opts.Wordlist))
			return 1
		}
		wordlistParams = wordlists.ParseFileContent(string(content))
		resolvedWordlist = wlPath
		log.Info(fmt.Sprintf("loaded %d parameter(s) from wordlist: '%s'", len(wordlistParams), opts.Wordlist))
	}

	threads := opts.Threads
	if threads < 1 {
		threads = 1
	}
	if threads > 5 {
		if !opts.Silent {
			log.Warning(fmt.Sprintf("thread count clamped to maximum 5 (requested: %d)", opts.Threads))
		}
		threads = 5
	}

	depth := opts.Depth
	if depth < 1 {
		depth = 1
	}
	if depth > 5 {
		if !opts.Silent {
			log.Warning(fmt.Sprintf("crawl depth clamped to maximum 5 (requested: %d)", opts.Depth))
		}
		depth = 5
	}

	maxURLs := opts.MaxURLs
	if maxURLs < 1 {
		maxURLs = 1
	}
	if maxURLs > 200 {
		if !opts.Silent {
			log.Warning(fmt.Sprintf("max-urls clamped to maximum 200 (requested: %d)", opts.MaxURLs))
		}
		maxURLs = 200
	}

	type scanItem struct {
		URL        string
		Method     string
		Postfields map[string]string
	}

	var scanQueue []scanItem
	seenURLSigs := map[string]bool{}
	seenFormSigs := map[string]bool{}

	for _, u := range validTargets {
		seenURLSigs[crawler.URLSignature(u)] = true
		method := "GET"
		if len(customPostfields) > 0 {
			method = "POST"
		}
		scanQueue = append(scanQueue, scanItem{URL: u, Method: method, Postfields: customPostfields})
	}

	if opts.Crawl {
		crawlManager := browser.NewManager(opts.Browser, isHeadless, opts.Timeout, customHeaders, nil)
		crawlSess, err := crawlManager.NewSession()
		if err != nil {
			log.Error("crawler browser start failed: " + err.Error())
			crawlManager.Close()
		} else {
			var crawlLog *logger.Logger
			if !opts.Silent {
				crawlLog = log
			}
			for _, seed := range validTargets {
				discovered := crawler.Run(crawlSess, seed, depth, maxURLs, crawlLog)
				for _, item := range discovered {
					if item.Method == "POST" {
						var names []string
						for name := range item.Postfields {
							names = append(names, name)
						}
						sig := crawler.FormSignature("POST", item.URL, names)
						if seenFormSigs[sig] {
							continue
						}
						seenFormSigs[sig] = true
						scanQueue = append(scanQueue, scanItem{URL: item.URL, Method: "POST", Postfields: item.Postfields})
					} else {
						sig := crawler.URLSignature(item.URL)
						if seenURLSigs[sig] {
							continue
						}
						seenURLSigs[sig] = true
						scanQueue = append(scanQueue, scanItem{URL: item.URL, Method: "GET"})
					}
				}
			}
			crawlSess.Close()
			crawlManager.Close()
		}
	}

	totalTargets := len(scanQueue)

	var allFindings []*models.XSSFinding
	var allParameters []*models.Parameter
	var resultsMu = make(chan struct{}, 1)

	buildConfig := func(item scanItem, targetCookies []models.CookieEntry, cookieHeader string, targetHeaders map[string]string) *models.ScanConfig {
		cfg := models.NewScanConfig()
		cfg.TargetURL = item.URL
		if item.Postfields != nil {
			cfg.Postfields = item.Postfields
		}
		cfg.BrowserType = opts.Browser
		cfg.Headless = isHeadless
		cfg.TimeoutMS = opts.Timeout
		cfg.DelayMin = opts.DelayMin
		cfg.DelayMax = opts.DelayMax
		cfg.Verbose = opts.Verbose
		cfg.OutputFile = resolvedOutput
		cfg.ScanModules = scanModules
		cfg.TargetParams = targetParams
		cfg.TargetParamContexts = targetParamContexts
		cfg.DefaultContext = defaultContext
		cfg.ExcludeParams = excludeParams
		cfg.IncludeHeaders = includeHeaders
		cfg.ExcludeHeaders = excludeHeaders
		cfg.WordlistPath = resolvedWordlist
		cfg.WordlistParams = wordlistParams
		cfg.MiningOnly = opts.Mining
		cfg.Headers = targetHeaders
		cfg.Cookies = targetCookies
		cfg.CookieString = cookieHeader
		cfg.Threads = threads
		cfg.Crawl = opts.Crawl
		cfg.Depth = depth
		cfg.MaxURLs = maxURLs
		return cfg
	}

	prepareCookiesAndHeaders := func(targetURL string) ([]models.CookieEntry, string, map[string]string) {
		cookies, cookieHeader := loadCookiesConfig(opts.Cookie, opts.CookieFile, baseDir, targetURL)
		targetHeaders := map[string]string{}
		for k, v := range customHeaders {
			targetHeaders[k] = v
		}
		if cookieHeader != "" {
			hasCookie := false
			for k := range targetHeaders {
				if strings.EqualFold(k, "Cookie") {
					hasCookie = true
					break
				}
			}
			if !hasCookie {
				targetHeaders["Cookie"] = cookieHeader
			}
		}
		return cookies, cookieHeader, targetHeaders
	}

	if threads > 1 && totalTargets > 1 {
		if !opts.Silent {
			log.Info(fmt.Sprintf("concurrency active: running %d parallel browser worker(s) across %d target(s)", threads, totalTargets))
		}

		sharedManager := browser.NewManager(opts.Browser, isHeadless, opts.Timeout, customHeaders, nil)
		sem := make(chan struct{}, threads)
		done := make(chan struct{})
		go func() {
			for idx, item := range scanQueue {
				idx, item := idx, item
				sem <- struct{}{}
				go func() {
					defer func() { <-sem }()
					if !opts.Silent {
						fmt.Printf("\n\033[1m\033[36m[*] target [%d/%d]: %s\033[0m\n", idx+1, totalTargets, item.URL)
					}
					cookies, cookieHeader, headers := prepareCookiesAndHeaders(item.URL)
					cfg := buildConfig(item, cookies, cookieHeader, headers)
					findings, parameters := runEngineSafe(cfg, log, sharedManager)
					resultsMu <- struct{}{}
					allFindings = append(allFindings, findings...)
					allParameters = append(allParameters, parameters...)
					<-resultsMu
					if opts.Silent && cfg.MiningOnly {
						printSilentReflections(parameters)
					}
				}()
			}
			for i := 0; i < threads; i++ {
				sem <- struct{}{}
			}
			sharedManager.Close()
			close(done)
		}()
		<-done
	} else {
		for idx, item := range scanQueue {
			if !opts.Silent && totalTargets > 1 {
				fmt.Printf("\n\033[1m\033[36m[*] target [%d/%d]: %s\033[0m\n", idx+1, totalTargets, item.URL)
			}
			cookies, cookieHeader, headers := prepareCookiesAndHeaders(item.URL)
			cfg := buildConfig(item, cookies, cookieHeader, headers)
			findings, parameters := runEngineSafe(cfg, log, nil)
			allFindings = append(allFindings, findings...)
			allParameters = append(allParameters, parameters...)

			if !opts.Silent && totalTargets == 1 {
				rep := reporter.New(findings, parameters, log, cfg.MiningOnly, opts.Silent)
				rep.RenderConsole()
			} else if opts.Silent && cfg.MiningOnly {
				printSilentReflections(parameters)
			}
		}
	}

	if !opts.Silent && totalTargets > 1 {
		fmt.Printf("\n\033[1m\033[36m[*] multi-target scan summary (%d targets scanned):\033[0m\n", totalTargets)
		rep := reporter.New(allFindings, allParameters, log, opts.Mining, opts.Silent)
		rep.RenderConsole()
	}

	if resolvedOutput != "" {
		rep := reporter.New(allFindings, allParameters, log, opts.Mining, opts.Silent)
		if err := rep.ExportJSON(resolvedOutput); err != nil {
			log.Error("failed to write report: " + err.Error())
			return 1
		}
	}

	return 0
}

// runEngineSafe runs one target scan and converts an unexpected internal panic
// into an error so a single target cannot crash the whole process.
func runEngineSafe(cfg *models.ScanConfig, log *logger.Logger, bm *browser.Manager) (findings []*models.XSSFinding, parameters []*models.Parameter) {
	defer func() {
		if r := recover(); r != nil {
			log.Error(fmt.Sprintf("scan aborted by an internal error: %v", r))
		}
	}()
	return scanner.NewEngine(cfg, log, bm).Run()
}

func printSilentReflections(parameters []*models.Parameter) {
	for _, p := range parameters {
		for _, r := range p.Reflections {
			if r.Reflected {
				tagStr := ""
				if r.Tags != "" {
					tagStr = fmt.Sprintf(", tag: <%s>", r.Tags)
				}
				fmt.Printf("\033[1m\033[32m[REFLECTED]\033[0m [%s] %s -> '%s' (%s%s)\n",
					p.Location, p.ActionURL, p.ParamName, strings.ToUpper(r.Context), tagStr)
			}
		}
	}
}

func handleShowOptions(opts *cliOptions) bool {
	handled := false
	if opts.ShowPayloads {
		handled = true
		for _, p := range payloads.AllPayloads() {
			fmt.Println(p.Payload)
		}
	}
	if opts.ShowHeaders {
		handled = true
		for _, h := range config.XSSHeaderTargets {
			fmt.Println(h.Name)
		}
	}
	if opts.ShowParams {
		handled = true
		seen := map[string]bool{}
		var all []string
		for _, p := range append(append([]string{}, config.GeneralParams...), config.RedirectParams...) {
			if !seen[p] {
				seen[p] = true
				all = append(all, p)
			}
		}
		fmt.Println(strings.Join(all, ", "))
	}
	return handled
}

func loadTargetURLs(opts *cliOptions) []string {
	var raw []string
	if strings.TrimSpace(opts.URL) != "" {
		raw = append(raw, strings.TrimSpace(opts.URL))
	}
	if strings.TrimSpace(opts.File) != "" {
		file, err := os.Open(opts.File)
		if err != nil {
			fmt.Fprintf(os.Stderr, "xsshunts: error: target file not found: '%s'\n", opts.File)
			os.Exit(2)
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			val := strings.TrimSpace(scanner.Text())
			if val != "" && !strings.HasPrefix(val, "#") {
				raw = append(raw, val)
			}
		}
	}
	if len(raw) == 0 && stdinHasData() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			val := strings.TrimSpace(scanner.Text())
			if val != "" && !strings.HasPrefix(val, "#") {
				raw = append(raw, val)
			}
		}
	}
	return dedupeStrings(raw)
}

func stdinHasData() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice == 0
}

func dedupeStrings(items []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, item := range items {
		if seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

func normalizeTargetURL(raw string) (string, bool) {
	val := strings.TrimSpace(raw)
	if val == "" {
		return "", false
	}
	if !strings.HasPrefix(val, "http://") && !strings.HasPrefix(val, "https://") {
		val = "http://" + val
	}
	if !utils.IsValidURL(val) {
		return "", false
	}
	return val, true
}

func parseCustomHeaders(rawHeaders []string) map[string]string {
	headers := map[string]string{}
	for _, item := range rawHeaders {
		for _, line := range strings.Split(item, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if idx := strings.Index(line, ":"); idx >= 0 {
				key := strings.TrimSpace(line[:idx])
				value := strings.TrimSpace(line[idx+1:])
				if key != "" {
					headers[key] = value
				}
			}
		}
	}
	return headers
}

func parseScanModules(scanStr string) map[string]bool {
	tokens := []string{}
	for _, t := range strings.Split(scanStr, ",") {
		t = strings.ToLower(strings.TrimSpace(t))
		if t != "" {
			tokens = append(tokens, t)
		}
	}
	if len(tokens) == 0 {
		return map[string]bool{"get": true, "post": true}
	}
	for _, t := range tokens {
		if t == "all" {
			return map[string]bool{"get": true, "post": true, "path": true, "fragment": true, "header": true}
		}
	}
	valid := map[string]bool{"get": true, "post": true, "path": true, "fragment": true, "header": true}
	selected := map[string]bool{}
	for _, tok := range tokens {
		switch {
		case valid[tok]:
			selected[tok] = true
		case tok == "dom":
			selected["get"] = true
		case tok == "paths" || tok == "link" || tok == "links":
			selected["path"] = true
		case tok == "fragments" || tok == "hash":
			selected["fragment"] = true
		case tok == "headers" || tok == "head":
			selected["header"] = true
		}
	}
	if len(selected) == 0 {
		return map[string]bool{"get": true, "post": true}
	}
	return selected
}

func parseTargetParams(paramArgs []string) ([]string, map[string]string) {
	var params []string
	contexts := map[string]string{}
	for _, item := range paramArgs {
		for _, piece := range strings.Split(item, ",") {
			piece = strings.TrimSpace(piece)
			if piece == "" {
				continue
			}
			if strings.Contains(piece, ":") {
				parts := strings.SplitN(piece, ":", 2)
				name := strings.TrimSpace(parts[0])
				ctx := detection.NormalizeContextName(strings.TrimSpace(parts[1]))
				if name != "" {
					if !containsFold(params, name) {
						params = append(params, name)
					}
					if ctx != "" {
						contexts[strings.ToLower(name)] = ctx
					}
				}
			} else if !containsFold(params, piece) {
				params = append(params, piece)
			}
		}
	}
	return params, contexts
}

func containsFold(items []string, target string) bool {
	for _, item := range items {
		if strings.EqualFold(item, target) {
			return true
		}
	}
	return false
}

func parseExcludeParams(raw string) []string {
	var out []string
	for _, p := range strings.Split(raw, ",") {
		cleaned := strings.ToLower(strings.TrimSpace(p))
		if cleaned != "" {
			out = append(out, cleaned)
		}
	}
	return out
}

func parseHeaderList(rawList []string) []string {
	var out []string
	for _, item := range rawList {
		for _, h := range strings.Split(item, ",") {
			cleaned := strings.TrimSpace(h)
			if cleaned != "" && !containsFold(out, cleaned) {
				out = append(out, cleaned)
			}
		}
	}
	return out
}

var rootedPathRe = regexp.MustCompile(`^[a-zA-Z]:[/\\]`)

func resolveOutputPath(userPath, baseDir string) string {
	raw := strings.TrimSpace(userPath)
	isRooted := strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "\\") || rootedPathRe.MatchString(raw) || filepath.IsAbs(raw)
	if isRooted {
		_ = os.MkdirAll(filepath.Dir(raw), 0o755)
		return raw
	}
	target := filepath.Join(baseDir, "output", raw)
	_ = os.MkdirAll(filepath.Dir(target), 0o755)
	return target
}

func resolveWordlistPath(userPath, baseDir string) (string, bool) {
	raw := strings.TrimSpace(userPath)
	if info, err := os.Stat(raw); err == nil && !info.IsDir() {
		return raw, true
	}
	alt := filepath.Join(baseDir, raw)
	if info, err := os.Stat(alt); err == nil && !info.IsDir() {
		return alt, true
	}
	return "", false
}

// ---- cookie loading ----

func parseCookieText(text, targetURL string) []models.CookieEntry {
	var cookies []models.CookieEntry
	text = strings.TrimSpace(text)
	if text == "" {
		return cookies
	}

	if strings.HasPrefix(text, "[") {
		var arr []map[string]interface{}
		if err := json.Unmarshal([]byte(text), &arr); err == nil {
			for _, item := range arr {
				name, _ := item["name"].(string)
				value, _ := item["value"].(string)
				if name == "" {
					continue
				}
				entry := models.CookieEntry{Name: name, Value: value}
				if domain, ok := item["domain"].(string); ok {
					entry.Domain = domain
				}
				if p, ok := item["path"].(string); ok {
					entry.Path = p
				}
				if entry.Domain == "" {
					entry.URL = targetURL
				}
				cookies = append(cookies, entry)
			}
			return cookies
		}
	}

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || (strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "#HttpOnly_")) {
			continue
		}
		line = strings.TrimPrefix(line, "#HttpOnly_")
		if strings.Contains(line, "\t") {
			parts := strings.Split(line, "\t")
			if len(parts) >= 7 {
				entry := models.CookieEntry{
					Name:  strings.TrimSpace(parts[5]),
					Value: strings.TrimSpace(parts[6]),
				}
				if domain := strings.TrimSpace(parts[0]); domain != "" {
					entry.Domain = domain
				}
				if p := strings.TrimSpace(parts[2]); p != "" {
					entry.Path = p
				}
				if entry.Domain == "" {
					entry.URL = targetURL
				}
				if entry.Name != "" {
					cookies = append(cookies, entry)
				}
				continue
			}
		}
		for _, pair := range strings.Split(line, ";") {
			pair = strings.TrimSpace(pair)
			if idx := strings.Index(pair, "="); idx > 0 {
				entry := models.CookieEntry{
					Name:  strings.TrimSpace(pair[:idx]),
					Value: strings.TrimSpace(pair[idx+1:]),
					URL:   targetURL,
				}
				if entry.Name != "" {
					cookies = append(cookies, entry)
				}
			}
		}
	}
	return cookies
}

func loadCookiesConfig(rawCookie, cookieFile, baseDir, targetURL string) ([]models.CookieEntry, string) {
	var all []models.CookieEntry

	if strings.TrimSpace(cookieFile) != "" {
		path := strings.TrimSpace(cookieFile)
		if _, err := os.Stat(path); err != nil {
			alt := filepath.Join(baseDir, path)
			if _, altErr := os.Stat(alt); altErr == nil {
				path = alt
			} else {
				fmt.Fprintf(os.Stderr, "xsshunts: error: cookie file not found: '%s'\n", cookieFile)
				os.Exit(2)
			}
		}
		if content, err := os.ReadFile(path); err == nil {
			all = append(all, parseCookieText(string(content), targetURL)...)
		}
	}

	if strings.TrimSpace(rawCookie) != "" {
		val := strings.TrimSpace(rawCookie)
		if content, err := os.ReadFile(val); err == nil {
			all = append(all, parseCookieText(string(content), targetURL)...)
		} else if content, err := os.ReadFile(filepath.Join(baseDir, val)); err == nil {
			all = append(all, parseCookieText(string(content), targetURL)...)
		} else {
			all = append(all, parseCookieText(val, targetURL)...)
		}
	}

	var final []models.CookieEntry
	indexByName := map[string]int{}
	for _, c := range all {
		if idx, ok := indexByName[c.Name]; ok {
			final[idx] = c
			continue
		}
		indexByName[c.Name] = len(final)
		final = append(final, c)
	}

	var parts []string
	for _, c := range final {
		parts = append(parts, c.Name+"="+c.Value)
	}
	header := strings.Join(parts, "; ")
	return final, header
}

// runUpdate checks GitHub for the latest release and installs it.
func runUpdate() int {
	fmt.Println("[*] checking GitHub for the latest release...")
	release, err := updater.FetchLatest()
	if err != nil {
		fmt.Fprintf(os.Stderr, "xsshunts: error: update check failed: %v\n", err)
		return 1
	}

	current := appmeta.Version
	fmt.Printf("[*] current version : v%s\n", current)
	fmt.Printf("[*] latest release  : %s\n", release.TagName)

	if !updater.IsNewer(current, release.TagName) {
		fmt.Printf("[+] xsshunts is up to date\n")
		return 0
	}

	asset := updater.FindAsset(release, runtime.GOOS, runtime.GOARCH)
	if asset == nil {
		fmt.Fprintf(os.Stderr, "xsshunts: error: no release asset for %s/%s; download manually: %s\n",
			runtime.GOOS, runtime.GOARCH, release.HTMLURL)
		return 1
	}

	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "xsshunts: error: could not locate current executable: %v\n", err)
		return 1
	}

	fmt.Printf("[*] downloading %s (%.1f MB)...\n", asset.Name, float64(asset.Size)/1048576)
	newPath, err := updater.DownloadWithChecksum(release, asset, filepath.Dir(exe))
	if err != nil {
		fmt.Fprintf(os.Stderr, "xsshunts: error: update failed: %v\n", err)
		return 1
	}

	result, err := updater.ReplaceExecutable(newPath)
	if err != nil {
		_ = os.Remove(newPath)
		fmt.Fprintf(os.Stderr, "xsshunts: error: update failed: %v\n", err)
		return 1
	}

	if result.Manual {
		fmt.Printf("[+] new version downloaded: %s\n", result.Path)
		fmt.Println("[!] close xsshunts, then replace the existing executable with the downloaded file")
		return 0
	}

	fmt.Printf("[+] xsshunts updated: v%s -> %s (%s)\n", current, release.TagName, result.Path)
	return 0
}
