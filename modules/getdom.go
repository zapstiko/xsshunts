package modules

import (
	"fmt"
	"strings"

	"github.com/zapstiko/xsshunts/browser"
	"github.com/zapstiko/xsshunts/detection"
	"github.com/zapstiko/xsshunts/logger"
	"github.com/zapstiko/xsshunts/models"
	"github.com/zapstiko/xsshunts/payloads"
	"github.com/zapstiko/xsshunts/utils"
)

// RunGetDOMXSS performs Step 2: reflected GET and DOM parameter payload testing.
func RunGetDOMXSS(sess *browser.Session, parameters []*models.Parameter, cfg *models.ScanConfig,
	log *logger.Logger, waf *detection.WAFManager) []*models.XSSFinding {

	if log != nil {
		log.Action("testing for reflected XSS vulnerabilities (GET & DOM)...")
	}

	findings := []*models.XSSFinding{}
	testedPayloads := map[string]bool{}
	testedParams := map[string]bool{}

	var targetParams []*models.Parameter
	for _, p := range parameters {
		if p.Location == "GET" || p.Location == "DOM" {
			targetParams = append(targetParams, p)
		}
	}

	for _, param := range targetParams {
		paramKey := strings.ToLower(param.ActionURL) + "|" + strings.ToLower(param.ParamName)
		if testedParams[paramKey] {
			continue
		}
		testedParams[paramKey] = true

		contextName := "html"
		if param.Location == "DOM" {
			contextName = "dom_js_html"
		}
		if param.CustomContext != "" {
			contextName = param.CustomContext
		} else if len(param.Reflections) > 0 {
			var reflectedCtx []string
			for _, r := range param.Reflections {
				if r.Reflected && r.Context != "unknown" {
					reflectedCtx = append(reflectedCtx, r.Context)
				}
			}
			if len(reflectedCtx) > 0 {
				contextName = detection.ResolveContextName(reflectedCtx[0], param.Location)
			}
		}

		payloadKeys := detection.GetPayloadKeysForContext(contextName)
		if len(payloadKeys) == 0 {
			continue
		}

		if log != nil {
			log.StartParamTest(param.ParamName, param.Location, contextName)
			log.Debug(fmt.Sprintf("queueing %d payload(s) for '%s' [%s] in %s context", len(payloadKeys), param.ParamName, param.Location, contextName))
		}

		for _, payloadKey := range payloadKeys {
			testKey := strings.ToLower(param.ActionURL) + "|" + strings.ToLower(param.ParamName) + "|" + payloadKey
			if testedPayloads[testKey] {
				continue
			}
			testedPayloads[testKey] = true

			payloadData := payloads.GetPayloadData(payloadKey)
			if payloadData == nil {
				continue
			}

			delayMin, delayMax := cfg.GetDelays()
			utils.DelayMs(delayMin, delayMax)

			pocURL := utils.BuildPayloadedURL(param.ActionURL, param.ParamName, payloadData.Payload)
			out := runNavProbe(sess, pocURL, payloadData, cfg, waf, log)

			finalXSS := 0
			if out.XSScan == 1 {
				finalXSS = 1
			}
			confidence := detection.CalculateConfidence(out.XSScan, out.XSMatch)

			finding := models.NewXSSFinding()
			finding.Endpoint = param.ActionURL
			finding.ParamName = param.ParamName
			finding.Context = contextName
			finding.PayloadName = payloadData.Name
			finding.PayloadKey = payloadKey
			finding.PayloadValue = payloadData.Payload
			finding.RequestMethod = param.Location
			finding.RequestURL = pocURL
			finding.XSS = finalXSS
			finding.Confidence = confidence
			finding.XSScan = out.XSScan
			finding.XSMatch = out.XSMatch
			finding.ResponseURL = out.ResponseURL
			finding.ResponseHeaders = out.ResponseHeaders
			finding.Text = out.Text
			finding.CreatedAt = utils.CurrentTime()
			finding.ProofOfConcept = pocURL

			executedDialog := ""
			if out.XSScan == 1 {
				executedDialog = fmt.Sprintf("%s('%d')", payloadData.DialogType, payloadData.ExpectedValue)
			}

			if log != nil {
				log.TestBlock(logger.TestBlockOpts{
					Method:      param.Location,
					ParamName:   param.ParamName,
					Context:     contextName,
					PayloadName: payloadData.Name,
					PayloadStr:  payloadData.Payload,
					RequestDesc: "GET " + pocURL,
					Confidence:  confidence,
					Dialog:      executedDialog,
					IsXSS:       finalXSS == 1,
					IsMatch:     out.XSMatch == 1 && finalXSS == 0,
				})
			}

			if finalXSS == 1 {
				findings = append(findings, finding)
				if log != nil {
					log.Debug(fmt.Sprintf("verified XSS found for '%s', halting further tests for this param", param.ParamName))
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
