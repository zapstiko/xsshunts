package modules

import (
	"fmt"
	"net/url"

	"github.com/zapstiko/xsshunts/browser"
	"github.com/zapstiko/xsshunts/detection"
	"github.com/zapstiko/xsshunts/logger"
	"github.com/zapstiko/xsshunts/models"
	"github.com/zapstiko/xsshunts/payloads"
	"github.com/zapstiko/xsshunts/utils"
)

// urlParse is a tiny wrapper used across modules.
func urlParse(raw string) (*url.URL, error) {
	return url.Parse(raw)
}

// toInt converts a JavaScript number result to int.
func toInt(v interface{}) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return int(n)
	case int64:
		return int(n)
	default:
		return -1
	}
}

// navOutcome is the result of one page-load XSS probe.
type navOutcome struct {
	XSScan          int
	XSMatch         int
	Text            string
	ResponseURL     string
	ResponseHeaders map[string]string
}

// runNavProbe loads a payloaded URL, waits for a possible dialog, and checks DOM matches.
func runNavProbe(sess *browser.Session, targetURL string, payloadData *payloads.PayloadData,
	cfg *models.ScanConfig, waf *detection.WAFManager, log *logger.Logger) navOutcome {

	out := navOutcome{}
	sess.ExpectDialog(payloadData.DialogType, payloadData.ExpectedValue)
	defer sess.ClearDialog()

	resp, err := sess.Goto(targetURL)
	if err != nil {
		out.Text = utils.CleanErrorText(err.Error())
		return out
	}

	sess.WaitNetworkIdle(3000)
	out.ResponseURL = sess.PageURL()

	var headers map[string]string
	if resp != nil {
		headers, _ = resp.AllHeaders()
		out.ResponseHeaders = headers
		out.Text = fmt.Sprintf("HTTP %d %s", resp.Status(), resp.StatusText())
	}

	html, _ := sess.Content()
	if log != nil {
		log.Debug(fmt.Sprintf("probe returned %s (%d chars)", out.Text, len(html)))
	}

	if waf != nil && resp != nil && cfg != nil {
		waf.HandleResponse(resp.Status(), headers, html, cfg)
	}

	if sess.DialogMatched() {
		out.XSScan = 1
	}
	if out.XSScan == 0 && payloadData.CheckForMatchEnabled() && utils.DetectMatch(html, payloadData) {
		out.XSMatch = 1
		if log != nil {
			log.Debug(fmt.Sprintf("DOM match confirmed for payload '%s'", payloadData.Name))
		}
	}
	return out
}
