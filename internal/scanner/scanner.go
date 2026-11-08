// Package scanner coordinates mining, reflection analysis, vector modules and
// the worker pool that ties them together.
package scanner

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/zapstiko/xsshunts/internal/config"
	"github.com/zapstiko/xsshunts/internal/models"
	"github.com/zapstiko/xsshunts/internal/modules"
	"github.com/zapstiko/xsshunts/internal/reporter"
	"github.com/zapstiko/xsshunts/internal/utils"
)

// Banner is the ASCII art shown at startup.
const Banner = `

  ██╗  ██╗    ███████╗    ███████╗    ██╗  ██╗    ██╗   ██╗    ███╗   ██╗    ████████╗    ███████╗
  ╚██╗██╔╝    ██╔════╝    ██╔════╝    ╚██╗██╔╝    ██║   ██║    ████╗  ██║    ╚══██╔══╝    ██╔════╝
   ╚███╔╝     ███████╗    ███████╗     ╚███╔╝     ██║   ██║    ██╔██╗ ██║       ██║       ███████╗
   ██╔██╗     ╚════██║    ╚════██║     ██╔██╗     ██║   ██║    ██║╚████║       ██║       ╚════██║
  ██╔╝ ██╗    ███████║    ███████║    ██╔╝ ██╗    ╚██████╔╝    ██║ ╚███║       ██║       ███████║
  ╚═╝  ╚═╝    ╚══════╝    ╚══════╝    ╚═╝  ╚═╝     ╚═════╝     ╚═╝  ╚══╝       ╚═╝       ╚══════╝
`

var msRound time.Duration = time.Millisecond

// Run executes the full audit; returns a process exit code.
func Run(opts *config.Options) int {
	if !opts.Silent {
		fmt.Println(utils.C(utils.Cyan, Banner))
		fmt.Printf("%s v%s — automated multi-vector XSS hunting toolkit (Go)\n\n", utils.C(utils.Bold, "xsshunts"), config.Version)
	}

	targets, err := loadTargets(opts)
	if err != nil {
		fmt.Println(utils.C(utils.Red, "[!]") + " " + err.Error())
		return 2
	}
	if len(targets) == 0 {
		fmt.Println(utils.C(utils.Red, "[!]") + " no targets loaded (use -u, -f or stdin)")
		return 2
	}

	rep := reporter.New()
	sess, err := modules.NewSession(opts, rep)
	if err != nil {
		fmt.Println(utils.C(utils.Red, "[!]") + " " + err.Error())
		return 2
	}
	defer sess.CloseBrowser()
	for _, t := range targets {
		sess.RegisterTarget(t)
	}

	// optional crawl expansion
	if opts.Crawl {
		var seeds []string
		for _, t := range targets {
			seeds = append(seeds, t.URL)
		}
		sess.Step("crawling %d seed(s), depth %d, cap %d...", len(seeds), opts.Depth, opts.MaxURLs)
		discovered := modules.Crawl(sess, seeds, opts.Depth, opts.MaxURLs)
		fresh := sess.AddTargets(discovered)
		sess.Good("crawler expanded the target list to %d endpoint(s)", len(fresh))
		targets = append(targets, fresh...)
	}

	// worker pool: each worker owns one goroutine of the pipeline
	scopes := opts.ScanSet()
	var wg sync.WaitGroup
	work := make(chan models.Target, len(targets))
	for _, t := range targets {
		work <- t
	}
	close(work)
	for worker := 0; worker < opts.Threads; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range work {
				auditTarget(sess, t, scopes)
			}
		}()
	}
	wg.Wait()

	// summary + output files
	rep.Stats()
	written := []string{}
	if opts.Output != "" {
		if path, werr := rep.WriteJSON(opts.Output); werr == nil {
			written = append(written, "json: "+path)
		} else {
			sess.Warn("cannot write JSON report: %v", werr)
		}
	}
	if opts.HTMLReport != "" {
		if path, werr := rep.WriteHTML(opts.HTMLReport); werr == nil {
			written = append(written, "html: "+path)
		} else {
			sess.Warn("cannot write HTML report: %v", werr)
		}
	}
	if len(written) > 0 {
		fmt.Println("reports: " + strings.Join(written, " | "))
	}
	return 0
}

// auditTarget runs the full pipeline against one target.
func auditTarget(sess *modules.Session, t models.Target, scopes map[string]bool) {
	sess.Info("")
	sess.Step("target: %s", utils.C(utils.Bold, t.URL))

	// preflight: WAF + reachability
	resp, err := sess.HTTP.Get(t.URL, nil)
	if err != nil {
		sess.Warn("target unreachable (%v); browser probes will still be attempted", err)
	} else if len(resp.WAF) > 0 {
		sess.AddWAF(resp.WAF)
	} else {
		sess.Info("  %s reachable (status %d, %d bytes, %s)", utils.C(utils.Green, "[ok]"), resp.Status, len(resp.Body), resp.Duration.Round(msRound))
	}

	// step 0: mining
	sess.Step("mining parameters...")
	d := modules.Discover(sess, t)
	total := len(d.GetParams) + len(d.PostParams)
	for _, p := range d.GetParams {
		sess.Good("  param %q [%s]", p.Name, p.Source)
	}
	for _, f := range d.Forms {
		sess.Good("  form %s %s (%d field(s))", f.Method, f.Action, len(f.Fields))
	}
	if total == 0 && len(d.Forms) == 0 {
		sess.Warn("  no injectable parameters discovered")
	}

	// step 1: reflection analysis
	sess.Step("reflection analysis...")
	for _, p := range d.GetParams {
		sess.Sleep(true)
		r, rerr := modules.AnalyzeReflection(sess, t, models.VectorGet, p.Name, p.Context)
		reportReflection(sess, models.VectorGet, r, rerr)
	}
	dataNames := dataFieldNames(t.Data)
	for _, p := range d.PostParams {
		if t.Data != "" && !contains(dataNames, p.Name) {
			continue
		}
		sess.Sleep(true)
		r, rerr := modules.AnalyzeReflection(sess, t, models.VectorPost, p.Name, "")
		reportReflection(sess, models.VectorPost, r, rerr)
	}

	if sess.Opts.MiningOnly {
		return
	}

	custom := customPayloads(sess)

	// steps 2..6: attack vectors
	if scopes[models.VectorGet] {
		sess.Step("vector: get")
		modules.ScanGet(sess, t, d.GetParams, custom)
	}
	if scopes[models.VectorPost] {
		sess.Step("vector: post")
		modules.ScanPost(sess, t, d.Forms, custom)
	}
	if scopes[models.VectorPath] {
		sess.Step("vector: path")
		modules.ScanPath(sess, t, custom)
	}
	if scopes[models.VectorFragment] {
		sess.Step("vector: fragment")
		modules.ScanFragment(sess, t, custom)
	}
	if scopes[models.VectorHeader] {
		sess.Step("vector: header")
		modules.ScanHeader(sess, t, custom)
	}
	sess.Report.Parameters += total
	sess.Report.Targets = append(sess.Report.Targets, t.URL)
}

func reportReflection(sess *modules.Session, source string, r *models.Reflection, err error) {
	if err != nil {
		sess.Warn("  reflection probe failed: %v", err)
		return
	}
	if r == nil {
		return
	}
	sess.Report.Reflections++
	sess.Good("  [%s] param %q %s", source, r.Param, r.Describe())
	sess.Info("      %s", utils.C(utils.Gray, "  "+r.MatrixLine()))
}

// loadTargets merges -u / -f / stdin into a validated target list.
func loadTargets(opts *config.Options) ([]models.Target, error) {
	var raw []string
	if opts.URL != "" {
		raw = append(raw, opts.URL)
	}
	if opts.File != "" {
		lines, ferr := utils.FileLines(opts.File)
		if ferr != nil {
			return nil, fmt.Errorf("cannot read targets file: %w", ferr)
		}
		raw = append(raw, lines...)
	}
	if !opts.Stdin && len(raw) == 0 && utils.IsStdinPiped() {
		opts.Stdin = true
	}
	if opts.Stdin {
		sc := bufio.NewScanner(os.Stdin)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				raw = append(raw, line)
			}
		}
	}
	var out []models.Target
	for _, line := range raw {
		u, verr := config.ValidateTarget(line)
		if verr != nil {
			fmt.Printf("[!] skipping invalid URL %q (%v)\n", line, verr)
			continue
		}
		out = append(out, models.Target{URL: u.String(), Method: "get", Data: opts.Data})
	}
	return out, nil
}

// customPayloads reads the --payload-file once.
func customPayloads(sess *modules.Session) []string {
	if sess.Opts.PayloadFile == "" {
		return nil
	}
	lines, err := utils.FileLines(sess.Opts.PayloadFile)
	if err != nil {
		sess.Warn("cannot read payload file %s: %v", sess.Opts.PayloadFile, err)
		return nil
	}
	return lines
}

// dataFieldNames lists field names inside raw POST data.
func dataFieldNames(data string) []string {
	vals, err := url.ParseQuery(data)
	if err != nil {
		return nil
	}
	out := []string{}
	for k := range vals {
		out = append(out, k)
	}
	return out
}

func contains(hay []string, needle string) bool {
	for _, item := range hay {
		if item == needle {
			return true
		}
	}
	return false
}
