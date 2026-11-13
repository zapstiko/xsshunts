// Package scanner orchestrates the 7-phase XSS audit pipeline.
package scanner

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/zapstiko/xsshunts/browser"
	"github.com/zapstiko/xsshunts/detection"
	"github.com/zapstiko/xsshunts/logger"
	"github.com/zapstiko/xsshunts/models"
	"github.com/zapstiko/xsshunts/modules"
	"github.com/zapstiko/xsshunts/utils"
)

// Engine executes the full audit for one target.
type Engine struct {
	Config         *models.ScanConfig
	Logger         *logger.Logger
	BrowserManager *browser.Manager
	OwnBrowser     bool
	WAF            *detection.WAFManager
	StartedAt      time.Time
}

// NewEngine creates a scan engine; when bm is nil the engine owns its browser.
func NewEngine(cfg *models.ScanConfig, log *logger.Logger, bm *browser.Manager) *Engine {
	own := bm == nil
	if bm == nil {
		bm = browser.NewManager(cfg.BrowserType, cfg.Headless, cfg.TimeoutMS, cfg.Headers, cfg.Cookies)
	}
	if log == nil {
		log = logger.NewLogger(cfg.Verbose, false)
	}
	if cfg.UserAgent != "" {
		bm.UserAgent = cfg.UserAgent
	}
	return &Engine{
		Config:         cfg,
		Logger:         log,
		BrowserManager: bm,
		OwnBrowser:     own,
		WAF:            detection.NewWAFManager(log),
		StartedAt:      time.Now(),
	}
}

// Run performs the complete 7-step audit and returns findings and parameters.
func (e *Engine) Run() ([]*models.XSSFinding, []*models.Parameter) {
	cfg := e.Config
	log := e.Logger

	if !utils.IsValidURL(cfg.TargetURL) {
		log.Error("Invalid target URL: " + cfg.TargetURL)
		return nil, nil
	}

	log.Info("target URL: " + cfg.TargetURL)
	log.Info(fmt.Sprintf("browser engine: %s (headless=%t)", cfg.BrowserType, cfg.Headless))
	if len(cfg.TargetParams) > 0 {
		var displays []string
		for _, tp := range cfg.TargetParams {
			ctx := cfg.TargetParamContexts[strings.ToLower(tp)]
			if ctx == "" {
				ctx = cfg.DefaultContext
			}
			if ctx != "" {
				displays = append(displays, tp+":"+ctx)
			} else {
				displays = append(displays, tp)
			}
		}
		log.Info("target parameter(s): " + strings.Join(displays, ", "))
	} else if cfg.DefaultContext != "" {
		log.Info("default context: " + cfg.DefaultContext)
	}
	if len(cfg.ExcludeParams) > 0 {
		log.Info("excluding parameter(s): " + strings.Join(cfg.ExcludeParams, ", "))
	}
	if cfg.WordlistPath != "" {
		log.Info(fmt.Sprintf("probing wordlist parameter(s): %s (%d params)", cfg.WordlistPath, len(cfg.WordlistParams)))
	}
	if len(cfg.Headers) > 0 {
		var names []string
		for h := range cfg.Headers {
			if strings.ToLower(h) != "cookie" {
				names = append(names, h)
			}
		}
		if len(names) > 0 {
			log.Info("custom HTTP header(s): " + strings.Join(names, ", "))
		}
	}
	if len(cfg.Cookies) > 0 {
		log.Info(fmt.Sprintf("custom cookie(s): %d cookie(s) loaded", len(cfg.Cookies)))
	}
	if cfg.MiningOnly {
		log.Info("mining mode active: parameter discovery and reflection analysis only")
	}
	var mods []string
	for _, m := range []string{"get", "post", "path", "fragment", "header"} {
		if cfg.HasModule(m) {
			mods = append(mods, m)
		}
	}
	log.Debug("scan scope modules: " + strings.Join(mods, ", "))

	if e.OwnBrowser {
		log.Debug(fmt.Sprintf("launching %s browser instance...", cfg.BrowserType))
	}
	sess, err := e.BrowserManager.NewSession()
	if err != nil {
		log.Error("unable to start browser: " + err.Error())
		if e.OwnBrowser {
			e.BrowserManager.Close()
		}
		return nil, nil
	}
	if e.BrowserManager.FallbackNotice != "" {
		log.Warning(e.BrowserManager.FallbackNotice)
	}
	defer func() {
		sess.Close()
		if e.OwnBrowser {
			log.Debug("closing browser resources...")
			e.BrowserManager.Close()
		}
	}()

	log.Debug("browser instance ready, beginning Step 0 (parameter discovery)...")

	parameters := modules.RunParameterMining(sess, cfg.TargetURL, cfg.Postfields,
		cfg.ExcludeParams, cfg.WordlistParams, log)

	if len(cfg.ExcludeParams) > 0 {
		excludeSet := map[string]bool{}
		for _, p := range cfg.ExcludeParams {
			excludeSet[strings.ToLower(p)] = true
		}
		var filtered []*models.Parameter
		for _, p := range parameters {
			if !excludeSet[strings.ToLower(p.ParamName)] {
				filtered = append(filtered, p)
			}
		}
		parameters = filtered
	}

	if len(cfg.TargetParams) > 0 {
		targetSet := map[string]bool{}
		for _, p := range cfg.TargetParams {
			targetSet[strings.ToLower(p)] = true
		}
		var filtered []*models.Parameter
		for _, p := range parameters {
			if targetSet[strings.ToLower(p.ParamName)] {
				filtered = append(filtered, p)
			}
		}
		existing := map[string]bool{}
		for _, p := range filtered {
			existing[strings.ToLower(p.ParamName)] = true
		}
		excludeSet := map[string]bool{}
		for _, p := range cfg.ExcludeParams {
			excludeSet[strings.ToLower(p)] = true
		}
		for _, tp := range cfg.TargetParams {
			if !existing[strings.ToLower(tp)] && !excludeSet[strings.ToLower(tp)] {
				originPath := originPathFor(cfg.TargetURL)
				p := models.NewParameter()
				p.ParamName = tp
				p.ParamValue = utils.RandomString(9)
				p.ActionURL = originPath
				p.Location = "GET"
				filtered = append(filtered, p)
			}
		}
		parameters = filtered
	}

	for _, p := range parameters {
		ctx := cfg.TargetParamContexts[strings.ToLower(p.ParamName)]
		if ctx == "" {
			ctx = cfg.DefaultContext
		}
		if ctx != "" {
			p.CustomContext = ctx
		}
	}

	log.Debug(fmt.Sprintf("Step 0 complete: total %d parameter(s) registered", len(parameters)))

	var allFindings []*models.XSSFinding

	runSteps := func() {
		if len(parameters) > 0 {
			log.Debug("beginning Step 1 (reflection analysis)...")
			parameters = modules.RunReflectionEngine(sess, parameters, log, e.WAF, cfg)
			log.Debug(fmt.Sprintf("Step 1 complete: reflections evaluated for %d parameter(s)", len(parameters)))

			if cfg.MiningOnly {
				log.Info(fmt.Sprintf("mining finished in %s", e.elapsedString()))
				return
			}

			if cfg.HasModule("get") {
				log.Debug("beginning Step 2 (reflected & DOM XSS testing)...")
				findings := modules.RunGetDOMXSS(sess, parameters, cfg, log, e.WAF)
				allFindings = append(allFindings, findings...)
				log.Debug(fmt.Sprintf("Step 2 complete: %d finding(s)", len(findings)))
			}

			if cfg.HasModule("post") {
				log.Debug("beginning Step 3 (POST form-based XSS testing)...")
				findings := modules.RunPostBasedXSS(sess, parameters, cfg, log, e.WAF)
				allFindings = append(allFindings, findings...)
				log.Debug(fmt.Sprintf("Step 3 complete: %d finding(s)", len(findings)))
			}
		} else {
			if cfg.MiningOnly {
				log.Warning("no parameters discovered for mining")
				return
			}
			log.Warning("no parameters discovered; checking path, fragment, and header vectors...")
		}

		if cfg.HasModule("path") {
			log.Debug("beginning Step 4 (path-based XSS testing)...")
			findings := modules.RunPathBasedXSS(sess, cfg.TargetURL, cfg, log, e.WAF)
			allFindings = append(allFindings, findings...)
			log.Debug(fmt.Sprintf("Step 4 complete: %d finding(s)", len(findings)))
		}

		if cfg.HasModule("fragment") {
			log.Debug("beginning Step 5 (fragment-based XSS testing)...")
			findings := modules.RunFragmentBasedXSS(sess, cfg.TargetURL, cfg, log, e.WAF)
			allFindings = append(allFindings, findings...)
			log.Debug(fmt.Sprintf("Step 5 complete: %d finding(s)", len(findings)))
		}

		if cfg.HasModule("header") {
			log.Debug("beginning Step 6 (header-based XSS testing)...")
			findings := modules.RunHeaderBasedXSS(e.BrowserManager, cfg.TargetURL, cfg, log, e.WAF)
			allFindings = append(allFindings, findings...)
			log.Debug(fmt.Sprintf("Step 6 complete: %d finding(s)", len(findings)))
		}
	}

	runSteps()

	log.Info(fmt.Sprintf("scan finished in %s", e.elapsedString()))
	return allFindings, parameters
}

func originPathFor(targetURL string) string {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return targetURL
	}
	originPath := parsed.Scheme + "://" + parsed.Host + parsed.Path
	if !strings.HasSuffix(originPath, "/") && parsed.Path == "" {
		originPath += "/"
	}
	return originPath
}

func (e *Engine) elapsedString() string {
	return fmt.Sprintf("%.2fs", time.Since(e.StartedAt).Seconds())
}
