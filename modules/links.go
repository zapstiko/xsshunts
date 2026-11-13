package modules

import (
	"fmt"
	"strings"

	"github.com/zapstiko/xsshunts/browser"
	"github.com/zapstiko/xsshunts/detection"
	"github.com/zapstiko/xsshunts/logger"
	"github.com/zapstiko/xsshunts/models"
	"github.com/zapstiko/xsshunts/parsers"
	"github.com/zapstiko/xsshunts/payloads"
	"github.com/zapstiko/xsshunts/utils"
)

// RunPathBasedXSS performs Step 4: payload injection into URL path segments.
func RunPathBasedXSS(sess *browser.Session, targetURL string, cfg *models.ScanConfig,
	log *logger.Logger, waf *detection.WAFManager) []*models.XSSFinding {

	testPaths := parsers.BuildTestPaths(targetURL)
	if len(testPaths) == 0 {
		return nil
	}

	if log != nil {
		log.Action(fmt.Sprintf("testing path-based injection points across %d path segment(s)...", len(testPaths)))
	}

	findings := []*models.XSSFinding{}
	payloadKeys := payloads.ContextMap["path_based"]
	testedPaths := map[string]bool{}

	for _, testPath := range testPaths {
		if log != nil {
			log.StartParamTest(testPath, "PATH", "path")
			log.Debug(fmt.Sprintf("queueing %d payload(s) for path '%s'", len(payloadKeys), testPath))
		}

		for _, payloadKey := range payloadKeys {
			testKey := strings.ToLower(testPath) + "|" + payloadKey
			if testedPaths[testKey] {
				continue
			}
			testedPaths[testKey] = true

			payloadData := payloads.GetPayloadData(payloadKey)
			if payloadData == nil {
				continue
			}

			if log != nil {
				log.Trying(payloadData.Name, payloadData.Payload)
			}

			delayMin, delayMax := cfg.GetDelays()
			utils.DelayMs(delayMin, delayMax)

			pocURL := utils.BuildPathPayloadURL(testPath, payloadData.Payload)
			out := runNavProbe(sess, pocURL, payloadData, cfg, waf, log)

			finalXSS := 0
			if out.XSScan == 1 {
				finalXSS = 1
			}
			confidence := detection.CalculateConfidence(out.XSScan, out.XSMatch)

			finding := models.NewXSSFinding()
			finding.Endpoint = testPath
			finding.ParamName = ""
			finding.Context = "path_based"
			finding.PayloadName = payloadData.Name
			finding.PayloadKey = payloadKey
			finding.PayloadValue = payloadData.Payload
			finding.RequestMethod = "PATH"
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
					Method:      "PATH",
					ParamName:   "",
					Context:     "path",
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
					log.Debug(fmt.Sprintf("verified path XSS found for '%s', halting further tests for this path", testPath))
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
