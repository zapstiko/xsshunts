package modules

import (
	"fmt"
	"strings"

	"github.com/zapstiko/xsshunts/browser"
	"github.com/zapstiko/xsshunts/config"
	"github.com/zapstiko/xsshunts/detection"
	"github.com/zapstiko/xsshunts/logger"
	"github.com/zapstiko/xsshunts/models"
	"github.com/zapstiko/xsshunts/payloads"
	"github.com/zapstiko/xsshunts/utils"
)

// buildTargetHeaders applies user include/exclude rules to the header target list.
func buildTargetHeaders(base []config.XSSHeaderTarget, includeHeaders, excludeHeaders []string) []config.XSSHeaderTarget {
	headers := append([]config.XSSHeaderTarget(nil), base...)

	for _, inc := range includeHeaders {
		cleaned := strings.TrimSpace(inc)
		if cleaned == "" {
			continue
		}
		exists := false
		for _, h := range headers {
			if strings.EqualFold(h.Name, cleaned) {
				exists = true
				break
			}
		}
		if exists {
			continue
		}
		cLow := strings.ToLower(cleaned)
		var contexts []string
		switch {
		case strings.Contains(cLow, "user-agent") || strings.Contains(cLow, "useragent"):
			contexts = []string{"header_based_useragent"}
		case strings.Contains(cLow, "cookie"):
			contexts = []string{"header_based_cookie"}
		case strings.Contains(cLow, "referer") || strings.Contains(cLow, "url") || strings.Contains(cLow, "uri"):
			contexts = []string{"header_based_url"}
		default:
			contexts = []string{"header_based_host", "header_based_basic"}
		}
		headers = append(headers, config.XSSHeaderTarget{Name: cleaned, Contexts: contexts})
	}

	if len(excludeHeaders) > 0 {
		excludeSet := map[string]bool{}
		for _, h := range excludeHeaders {
			if trimmed := strings.ToLower(strings.TrimSpace(h)); trimmed != "" {
				excludeSet[trimmed] = true
			}
		}
		var filtered []config.XSSHeaderTarget
		for _, h := range headers {
			if !excludeSet[strings.ToLower(h.Name)] {
				filtered = append(filtered, h)
			}
		}
		headers = filtered
	}
	return headers
}

// RunHeaderBasedXSS performs Step 6: injection via HTTP request headers.
func RunHeaderBasedXSS(bm *browser.Manager, targetURL string, cfg *models.ScanConfig,
	log *logger.Logger, waf *detection.WAFManager) []*models.XSSFinding {

	activeHeaders := buildTargetHeaders(config.XSSHeaderTargets, cfg.IncludeHeaders, cfg.ExcludeHeaders)

	if log != nil {
		log.Action(fmt.Sprintf("testing HTTP header injection points (%d headers)...", len(activeHeaders)))
		if len(cfg.IncludeHeaders) > 0 {
			log.Debug("custom included headers: " + strings.Join(cfg.IncludeHeaders, ", "))
		}
		if len(cfg.ExcludeHeaders) > 0 {
			log.Debug("custom excluded headers: " + strings.Join(cfg.ExcludeHeaders, ", "))
		}
	}

	findings := []*models.XSSFinding{}
	testedHeaders := map[string]bool{}

	for _, header := range activeHeaders {
		var payloadKeys []string
		for _, ctx := range header.Contexts {
			if keys, ok := payloads.ContextMap[ctx]; ok {
				payloadKeys = append(payloadKeys, keys...)
			}
		}

		if log != nil && len(payloadKeys) > 0 {
			log.StartParamTest(header.Name, "HEADER", "http_header")
			log.Debug(fmt.Sprintf("queueing %d payload(s) for header '%s'", len(payloadKeys), header.Name))
		}

		for _, payloadKey := range payloadKeys {
			testKey := strings.ToLower(header.Name) + "|" + strings.ToLower(targetURL) + "|" + payloadKey
			if testedHeaders[testKey] {
				continue
			}
			testedHeaders[testKey] = true

			payloadData := payloads.GetPayloadData(payloadKey)
			if payloadData == nil {
				continue
			}

			delayMin, delayMax := cfg.GetDelays()
			utils.DelayMs(delayMin, delayMax)

			extraHeaders := map[string]string{}
			customUA := ""
			if strings.EqualFold(header.Name, "User-Agent") {
				customUA = payloadData.Payload
			} else {
				extraHeaders[header.Name] = payloadData.Payload
			}

			sess, err := bm.NewSessionWith(extraHeaders, customUA)
			if err != nil {
				if log != nil {
					log.Debug(fmt.Sprintf("header context error for '%s': %s", header.Name, utils.CleanErrorText(err.Error())))
				}
				continue
			}

			out := runNavProbe(sess, targetURL, payloadData, cfg, waf, log)
			sess.Close()

			finalXSS := 0
			if out.XSScan == 1 {
				finalXSS = 1
			}
			confidence := detection.CalculateConfidence(out.XSScan, out.XSMatch)

			finding := models.NewXSSFinding()
			finding.Endpoint = targetURL
			finding.ParamName = "Header: " + header.Name
			finding.Context = "header_based"
			finding.PayloadName = payloadData.Name
			finding.PayloadKey = payloadKey
			finding.PayloadValue = payloadData.Payload
			finding.RequestMethod = "HEADER"
			finding.RequestURL = targetURL
			finding.XSS = finalXSS
			finding.Confidence = confidence
			finding.XSScan = out.XSScan
			finding.XSMatch = out.XSMatch
			finding.ResponseURL = out.ResponseURL
			finding.ResponseHeaders = out.ResponseHeaders
			finding.Text = out.Text
			finding.CreatedAt = utils.CurrentTime()
			finding.ProofOfConcept = fmt.Sprintf("%s: %s", header.Name, payloadData.Payload)

			executedDialog := ""
			if out.XSScan == 1 {
				executedDialog = fmt.Sprintf("%s('%d')", payloadData.DialogType, payloadData.ExpectedValue)
			}

			if log != nil {
				log.TestBlock(logger.TestBlockOpts{
					Method:      "HEADER",
					ParamName:   header.Name,
					Context:     "http_header",
					PayloadName: payloadData.Name,
					PayloadStr:  payloadData.Payload,
					RequestDesc: "GET " + targetURL,
					HeaderInfo:  fmt.Sprintf("%s: %s", header.Name, payloadData.Payload),
					Confidence:  confidence,
					Dialog:      executedDialog,
					IsXSS:       finalXSS == 1,
					IsMatch:     out.XSMatch == 1 && finalXSS == 0,
				})
			}

			if finalXSS == 1 {
				findings = append(findings, finding)
				if log != nil {
					log.Debug(fmt.Sprintf("verified header XSS found for '%s', halting further tests for this header", header.Name))
				}
				break
			} else if out.XSMatch == 1 {
				findings = append(findings, finding)
			}

			delayMin, delayMax = cfg.GetDelays()
			utils.DelayMs(delayMin, delayMax)
		}
	}
	return findings
}
