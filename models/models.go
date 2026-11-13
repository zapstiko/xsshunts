// Package models defines the scan data structures shared by all xsshunts modules.
package models

import (
	"sync"

	"github.com/google/uuid"
)

func newUUID() string {
	g, err := uuid.NewV7()
	if err != nil {
		return uuid.NewString()
	}
	return g.String()
}

// ReflectionResult captures one reflection observation for a parameter.
type ReflectionResult struct {
	ParameterName   string
	Reflected       bool
	Context         string
	Tags            string
	ResponseBody    string
	RequestURL      string
	RequestBody     string
	RequestMethod   string
	RequestHeaders  map[string]string
	ResponseHeaders map[string]string
	ResponseURL     string
	Text            string
	ReflectionUUID  string
}

// NewReflectionResult creates a reflection result with defaults.
func NewReflectionResult() *ReflectionResult {
	return &ReflectionResult{Context: "unknown", ReflectionUUID: newUUID()}
}

// Parameter is a single discovered injection point.
type Parameter struct {
	ParamName     string
	ParamValue    string
	Location      string // GET | POST | DOM
	ActionURL     string
	Tested        bool
	CustomContext string
	Reflections   []*ReflectionResult
	CharMatrix    map[string]string
	UUID          string
}

// NewParameter creates a GET parameter with a fresh UUID.
func NewParameter() *Parameter {
	return &Parameter{Location: "GET", UUID: newUUID()}
}

// XSSFinding is one confirmed or potential XSS result.
type XSSFinding struct {
	Endpoint        string
	ParamName       string
	Context         string
	PayloadName     string
	PayloadKey      string
	PayloadValue    string
	RequestMethod   string
	RequestURL      string
	RequestBody     string
	XSS             int
	Confidence      float64
	XSScan          int
	XSMatch         int
	ResponseURL     string
	RequestHeaders  map[string]string
	ResponseHeaders map[string]string
	ResponseBody    string
	Text            string
	CreatedAt       string
	ProofOfConcept  string
	FindingUUID     string
}

// NewXSSFinding creates a finding with a fresh UUID.
func NewXSSFinding() *XSSFinding {
	return &XSSFinding{FindingUUID: newUUID()}
}

// CookieEntry is one cookie supplied by the user.
type CookieEntry struct {
	Name   string
	Value  string
	Domain string
	Path   string
	URL    string
}

// ScanConfig is the full runtime configuration of one scan.
type ScanConfig struct {
	TargetURL           string
	Postfields          map[string]string
	BrowserType         string
	Headless            bool
	TimeoutMS           int
	Verbose             bool
	OutputFile          string
	ScanModules         map[string]bool
	TargetParams        []string
	TargetParamContexts map[string]string
	DefaultContext      string
	ExcludeParams       []string
	IncludeHeaders      []string
	ExcludeHeaders      []string
	WordlistPath        string
	WordlistParams      []string
	MiningOnly          bool
	Headers             map[string]string
	Cookies             []CookieEntry
	CookieString        string
	UserAgent           string
	Threads             int
	Crawl               bool
	Depth               int
	MaxURLs             int

	delayMu  sync.Mutex
	DelayMin int
	DelayMax int
}

// NewScanConfig initializes defaults for a scan config.
func NewScanConfig() *ScanConfig {
	return &ScanConfig{
		Postfields:          map[string]string{},
		ScanModules:         map[string]bool{"get": true, "post": true},
		TargetParamContexts: map[string]string{},
		Headers:             map[string]string{},
		Threads:             1,
		Depth:               2,
		MaxURLs:             50,
		BrowserType:         "firefox",
		Headless:            true,
		TimeoutMS:           15000,
		DelayMin:            3000,
		DelayMax:            5000,
	}
}

// GetDelays returns the current delay window.
func (c *ScanConfig) GetDelays() (int, int) {
	c.delayMu.Lock()
	defer c.delayMu.Unlock()
	return c.DelayMin, c.DelayMax
}

// DoubleDelays doubles the delay window (auto-throttle) and reports the transition.
func (c *ScanConfig) DoubleDelays() (oldMin, oldMax, newMin, newMax int) {
	c.delayMu.Lock()
	defer c.delayMu.Unlock()
	oldMin, oldMax = c.DelayMin, c.DelayMax
	newMin = oldMin * 2
	if newMin < 3000 {
		newMin = 3000
	}
	newMax = oldMax * 2
	if newMax < 6000 {
		newMax = 6000
	}
	c.DelayMin, c.DelayMax = newMin, newMax
	return
}

// HasModule reports whether a scan module is enabled.
func (c *ScanConfig) HasModule(m string) bool {
	return c.ScanModules[m]
}

// AddModule enables a scan module.
func (c *ScanConfig) AddModule(m string) {
	if c.ScanModules == nil {
		c.ScanModules = map[string]bool{}
	}
	c.ScanModules[m] = true
}
